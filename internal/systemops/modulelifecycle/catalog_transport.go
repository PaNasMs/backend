package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Validate both the URL and the address actually dialed. Following a redirect
// or resolving a DNS name must not relax the public HTTPS restriction.
func publicCatalogIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
		return false
	}
	for _, reserved := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2002::/16"} {
		if netip.MustParsePrefix(reserved).Contains(ip) {
			return false
		}
	}
	return !ip.Is6() || netip.MustParsePrefix("2000::/3").Contains(ip)
}
func catalogURL(value string, redirect bool) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (!redirect && (u.RawQuery != "" || u.ForceQuery)) || (u.Port() != "" && u.Port() != "443") {
		return nil, reject("Use an HTTPS repository URL without credentials, query or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, reject("Use a public HTTPS repository URL")
	}
	if ip, e := netip.ParseAddr(host); e == nil && !publicCatalogIP(ip) {
		return nil, reject("Use a public HTTPS repository URL")
	}
	u.Host = strings.ToLower(u.Host)
	return u, nil
}
func dialCatalog(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !publicCatalogIP(ip) {
			return nil, reject("Use a public HTTPS repository URL")
		}
	}
	for _, ip := range ips {
		conn, e := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		err = e
	}
	if err == nil {
		err = reject("Module repository address not found")
	}
	return nil, err
}
func downloadCatalog(ctx context.Context, value string, limit int64) ([]byte, error) {
	if _, err := catalogURL(value, false); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, value, nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: dialCatalog}
	defer transport.CloseIdleConnections()
	timeout := 10 * time.Second
	if limit > 2<<20 {
		timeout = time.Minute
	}
	client := http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return reject("Unexpected module download redirect")
		}
		_, err := catalogURL(req.URL.String(), true)
		return err
	}}
	res, err := client.Do(req)
	if err != nil {
		return nil, reject("Module catalog download failed. Check the internet connection and try again.")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, reject("Module catalog download failed. Check the internet connection and try again.")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, reject("Module download exceeds size limit")
	}
	return b, err
}

type catalogEnvelope struct {
	Algorithm string `json:"algorithm"`
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

func verifyCatalog(raw, envelope []byte, allowed []string, key func(string) (ed25519.PublicKey, error)) error {
	var sig catalogEnvelope
	if json.Unmarshal(envelope, &sig) != nil {
		return reject("Invalid module catalog signature")
	}
	for _, id := range allowed {
		if id == sig.Signer && signerPattern.MatchString(id) && sig.Algorithm == "Ed25519" {
			k, err := key(id)
			if err != nil {
				return err
			}
			if len(k) != ed25519.PublicKeySize || !ed25519.Verify(k, raw, sig.Signature) {
				return reject("Invalid module catalog signature")
			}
			return nil
		}
	}
	return reject("Untrusted module catalog signer")
}
