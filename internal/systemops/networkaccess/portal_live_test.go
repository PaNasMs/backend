package networkaccess

import (
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run only inside a disposable network namespace; the caller owns its lifecycle.
func TestLiveCaptivePortal(t *testing.T) {
	if os.Getenv("PANASMS_PORTAL_TEST_NETNS") != "1" {
		t.Skip("requires isolated server/client network namespaces")
	}
	if _, err := os.Stat("/sys/class/net/portal-test"); err != nil {
		t.Fatal(err)
	}
	oldState := portalState
	portalState = t.TempDir() + "/portal.json"
	t.Cleanup(func() { portalState = oldState })
	p := &portalController{instances: map[string]*portalInstance{}}
	t.Cleanup(p.close)
	rows := []Device{{Name: "portal-test", Profile: usbUUID, Connected: true, Addresses: []string{"10.181.240.1/24"}}}
	config := Config{USB: true, Enabled: true}
	if err := p.sync(config, rows); err != nil {
		t.Fatal(err)
	}
	client := func(args ...string) string {
		t.Helper()
		b, err := exec.Command("ip", append([]string{"netns", "exec", "panasms-portal-client-test"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("client: %v %s", err, b)
		}
		return string(b)
	}
	// DNS wire query avoids dependencies on dig/python on the NAS.
	_ = client("env", "PANASMS_PORTAL_DNS_CLIENT=1", os.Args[0], "-test.run=^TestLivePortalDNSClient$", "-test.v")
	raw := client("curl", "--noproxy", "*", "--max-time", "5", "-sS", "-D", "-", "-o", "/dev/null", "--resolve", "networkcheck.kde.org:80:10.181.240.2", "http://networkcheck.kde.org/")
	if !strings.Contains(raw, "302 Found") || !strings.Contains(raw, "Location: http://10.181.240.1/") {
		t.Fatal(raw)
	}
	// Changing from USB to AP uses the same scoped discovery path.
	rows[0].Profile = apUUID
	if err := p.sync(config, rows); err != nil {
		t.Fatal(err)
	}
	// Recreate a DNS child killed by a service failure.
	instance := p.instances["portal-test"]
	_ = instance.dns.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	if err := p.sync(config, rows); err != nil {
		t.Fatal(err)
	}
	_ = client("env", "PANASMS_PORTAL_DNS_CLIENT=1", os.Args[0], "-test.run=^TestLivePortalDNSClient$")
	if err := p.sync(Config{}, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/sys/class/net/portal-test"); err != nil {
		t.Fatal(err)
	}
	addresses, _ := net.InterfaceByName("portal-test")
	addrs, _ := addresses.Addrs()
	for _, a := range addrs {
		if a.String() == "10.181.240.2/32" {
			t.Fatal("alias retained after disable")
		}
	}
	if exists, err := portalTableExists(); err != nil || exists {
		t.Fatalf("firewall cleanup: %v %v", exists, err)
	}
}

func TestLivePortalDNSClient(t *testing.T) {
	if os.Getenv("PANASMS_PORTAL_DNS_CLIENT") != "1" {
		t.Skip("client helper")
	}
	// networkcheck.kde.org A / IN
	packet, _ := hex.DecodeString("1234010000010000000000000c6e6574776f726b636865636b036b6465036f72670000010001")
	conn, err := net.DialTimeout("udp4", "10.181.240.1:53", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1500)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 || net.IP(b[n-4:n]).String() != "10.181.240.2" {
		t.Fatalf("unexpected DNS: %x", b[:n])
	}
}
