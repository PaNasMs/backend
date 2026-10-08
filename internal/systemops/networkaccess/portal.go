package networkaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops/webaccess"
)

const portalTable = "panasms_access_portal"
const portalMarker = "PaNasMs direct access portal"

var portalState = "/run/panasms-access-portal.json"

var probeHosts = []string{
	"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com",
	"captive.apple.com", "www.msftconnecttest.com", "ipv6.msftconnecttest.com", "www.msftncsi.com",
	"networkcheck.kde.org", "connectivity-check.ubuntu.com", "nmcheck.gnome.org", "nmcheck.opensuse.org", "ping.archlinux.org",
}

type portalEndpoint struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Alias     string `json:"alias"`
}

type portalInstance struct {
	endpoint          portalEndpoint
	http              *http.Server
	dns               *exec.Cmd
	done              chan error
	httpPort, dnsPort int
	aliasOwned        bool
}

type portalController struct {
	instances map[string]*portalInstance
	rules     string
}

func portalEndpoints(c Config, rows []Device) []portalEndpoint {
	var result []portalEndpoint
	for _, d := range rows {
		if !d.Connected || d.Reserved || !(c.USB && d.Profile == usbUUID || c.Enabled && d.Profile == apUUID) {
			continue
		}
		for _, address := range d.Addresses {
			ip, subnet, err := net.ParseCIDR(address)
			if err != nil || ip.To4() == nil {
				continue
			}
			ip = ip.To4()
			bits, _ := subnet.Mask.Size()
			// DirectStart and the NM profile reserve .1 for the gateway and .20+ for DHCP.
			if bits != 24 || ip[3] != 1 {
				continue
			}
			alias := append(net.IP(nil), ip...)
			alias[3] = 2
			result = append(result, portalEndpoint{d.Name, ip.String(), alias.String()})
			break
		}
	}
	return result
}

func portalHandler(gateway string, port func() (int, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		p, err := port()
		if err != nil {
			http.Error(w, "Web interface configuration unavailable", http.StatusServiceUnavailable)
			return
		}
		destination := "http://" + gateway
		if p != 80 {
			destination += ":" + strconv.Itoa(p)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, destination+"/", http.StatusFound)
	})
}

func portalDNSArgs(e portalEndpoint, port int) []string {
	args := []string{"--keep-in-foreground", "--conf-file=/dev/null", "--no-hosts", "--bind-interfaces", "--listen-address=" + e.Gateway, "--port=" + strconv.Itoa(port), "--pid-file=", "--cache-size=150"}
	for _, host := range probeHosts {
		args = append(args, "--address=/"+host+"/"+e.Alias, "--local=/"+host+"/")
	}
	return args
}

func startPortal(e portalEndpoint, persist func() error) (_ *portalInstance, result error) {
	p := &portalInstance{endpoint: e, done: make(chan error, 1)}
	defer func() {
		if result != nil {
			p.close()
		}
	}()
	// Refuse an existing alias: it may belong to an administrator or another service.
	intf, err := net.InterfaceByName(e.Interface)
	if err != nil {
		return nil, err
	}
	addresses, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip != nil && ip.String() == e.Alias {
			return nil, fmt.Errorf("Captive portal address %s is already in use", e.Alias)
		}
	}
	if err = persist(); err != nil {
		return nil, err
	}
	if _, err = run("ip", "address", "add", e.Alias+"/32", "dev", e.Interface); err != nil {
		return nil, err
	}
	p.aliasOwned = true
	listener, err := net.Listen("tcp4", e.Alias+":0")
	if err != nil {
		return nil, err
	}
	p.httpPort = listener.Addr().(*net.TCPAddr).Port
	p.http = &http.Server{Handler: portalHandler(e.Gateway, webaccess.Default().Current), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	go p.http.Serve(listener)
	socket, err := net.ListenPacket("udp4", e.Gateway+":0")
	if err != nil {
		return nil, err
	}
	p.dnsPort = socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	p.dns = exec.Command("/usr/sbin/dnsmasq", portalDNSArgs(e, p.dnsPort)...)
	p.dns.Stderr = os.Stderr
	if err = p.dns.Start(); err != nil {
		return nil, err
	}
	go func() { p.done <- p.dns.Wait() }()
	// Do not install redirects until the DNS process has bound both transports.
	for attempt := 0; attempt < 20; attempt++ {
		select {
		case err := <-p.done:
			return nil, fmt.Errorf("Captive DNS failed: %v", err)
		default:
		}
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(e.Gateway, strconv.Itoa(p.dnsPort)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return p, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("Captive DNS did not start")
}

func (p *portalInstance) close() {
	if p.http != nil {
		p.http.Close()
	}
	if p.dns != nil && p.dns.Process != nil {
		_ = p.dns.Process.Kill()
	}
	// Only remove an address created by this instance.
	if p.aliasOwned {
		_, _ = run("ip", "address", "del", p.endpoint.Alias+"/32", "dev", p.endpoint.Interface)
	}
}

func portalRules(instances map[string]*portalInstance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n comment %q\n chain discovery {\n type nat hook prerouting priority -110; policy accept;\n", portalTable, portalMarker)
	names := make([]string, 0, len(instances))
	for name := range instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := instances[name]
		e := p.endpoint
		fmt.Fprintf(&b, "iifname %q ip daddr %s udp dport 53 redirect to :%d\n", e.Interface, e.Gateway, p.dnsPort)
		fmt.Fprintf(&b, "iifname %q ip daddr %s tcp dport 53 redirect to :%d\n", e.Interface, e.Gateway, p.dnsPort)
		// DNAT preserves the alias destination; REDIRECT would select the primary address.
		fmt.Fprintf(&b, "iifname %q ip daddr %s tcp dport 80 dnat to %s:%d\n", e.Interface, e.Alias, e.Alias, p.httpPort)
	}
	b.WriteString("}\n}\n")
	return b.String()
}

func portalTableExists() (bool, error) {
	raw, err := run("nft", "-j", "list", "tables", "ip")
	if err != nil {
		return false, err
	}
	var listed struct {
		NFTables []struct {
			Table *struct {
				Name    string
				Comment string
			}
		} `json:"nftables"`
	}
	if err = json.Unmarshal([]byte(raw), &listed); err != nil {
		return false, err
	}
	for _, row := range listed.NFTables {
		if row.Table != nil && row.Table.Name == portalTable {
			raw, err = run("nft", "-j", "list", "table", "ip", portalTable)
			if err != nil {
				return false, err
			}
			if err = json.Unmarshal([]byte(raw), &listed); err != nil {
				return false, err
			}
			for _, entry := range listed.NFTables {
				if entry.Table != nil && entry.Table.Comment == portalMarker {
					return true, nil
				}
			}
			return false, fmt.Errorf("An existing firewall table conflicts with the captive portal")
		}
	}
	return false, nil
}

func applyPortalRules(rules string) error {
	exists, err := portalTableExists()
	if err != nil {
		return err
	}
	if exists {
		rules = "delete table ip " + portalTable + "\n" + rules
	}
	if rules == "" {
		return nil
	}
	f, err := os.CreateTemp("/run", "panasms-portal-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(rules)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	_, err = run("nft", "-f", f.Name())
	return err
}

func (p *portalController) sync(c Config, rows []Device) error {
	desired := portalEndpoints(c, rows)
	wanted := map[string]portalEndpoint{}
	for _, e := range desired {
		wanted[e.Interface] = e
	}
	for name, instance := range p.instances {
		dead := true
		if i, err := net.InterfaceByName(name); err == nil {
			addresses, _ := i.Addrs()
			for _, a := range addresses {
				if a.String() == instance.endpoint.Alias+"/32" {
					dead = false
				}
			}
		}
		select {
		case <-instance.done:
			dead = true
		default:
		}
		if wanted[name] != instance.endpoint || dead {
			if err := applyPortalRules(""); err != nil {
				return err
			}
			p.rules = ""
			instance.close()
			delete(p.instances, name)
		}
	}
	for _, e := range desired {
		if p.instances[e.Interface] != nil {
			continue
		}
		// Persist cleanup intent before acquiring resources, including daemon crashes.
		instance, err := startPortal(e, func() error {
			owned := []portalEndpoint{e}
			for _, instance := range p.instances {
				owned = append(owned, instance.endpoint)
			}
			return write(portalState, owned)
		})
		if err != nil {
			return err
		}
		p.instances[e.Interface] = instance
	}
	rules := portalRules(p.instances)
	if len(p.instances) == 0 {
		rules = ""
	}
	exists, err := portalTableExists()
	if err != nil {
		return err
	}
	if rules != p.rules || (rules != "" && !exists) {
		if err = applyPortalRules(rules); err != nil {
			return err
		}
		p.rules = rules
	}
	return write(portalState, desired)
}

func cleanupPortal() error {
	if err := applyPortalRules(""); err != nil {
		return err
	}
	var endpoints []portalEndpoint
	if err := read(portalState, &endpoints); err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range endpoints {
		ip := net.ParseIP(e.Alias)
		if ip == nil || ip.To4() == nil || ip.To4()[3] != 2 || strings.ContainsAny(e.Interface, "/\x00\n") {
			continue
		}
		_, _ = run("ip", "address", "del", e.Alias+"/32", "dev", e.Interface)
	}
	return write(portalState, []portalEndpoint{})
}

func (p *portalController) close() {
	_ = applyPortalRules("")
	for _, instance := range p.instances {
		instance.close()
	}
	_ = cleanupPortal()
}

func runAccess(ctx context.Context) error {
	if err := cleanupPortal(); err != nil {
		return err
	}
	portal := &portalController{instances: map[string]*portalInstance{}}
	defer portal.close()
	for {
		if err := tickGuardedPortal(portal); err != nil {
			fmt.Fprintln(os.Stderr, "network access:", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
		}
	}
}
