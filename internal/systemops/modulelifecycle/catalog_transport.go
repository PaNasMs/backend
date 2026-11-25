package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
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

// catalogTimeout bounds each network operation of a download, like the socket
// timeout of module_catalog.py: a slow transfer that keeps delivering data is
// not cut off, a stalled one fails.
func catalogTimeout(limit int64) time.Duration {
	if limit > 2<<20 {
		return time.Minute
	}
	return 10 * time.Second
}

type catalogTransfer struct {
	dial    func(context.Context, string, string) (net.Conn, error)
	tls     *tls.Config
	timeout time.Duration
}

func downloadCatalog(ctx context.Context, value string, limit int64) ([]byte, error) {
	return catalogTransfer{dial: dialCatalog, timeout: catalogTimeout(limit)}.download(ctx, value, limit)
}

// idleConn fails any single read or write that waits longer than the
// per-operation timeout. Bounding the connection itself covers every read the
// HTTP client makes, including the TLS handshake and the drain of an
// intermediate redirect body, not only the final response body.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (t catalogTransfer) download(ctx context.Context, value string, limit int64) ([]byte, error) {
	if _, err := catalogURL(value, false); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, value, nil)
	if err != nil {
		return nil, err
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, stop := context.WithTimeout(ctx, t.timeout)
		defer stop()
		conn, err := t.dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return idleConn{Conn: conn, timeout: t.timeout}, nil
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: t.tls, TLSHandshakeTimeout: t.timeout, ResponseHeaderTimeout: t.timeout}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return reject("Unexpected module download redirect")
		}
		if _, err := catalogURL(req.URL.String(), true); err != nil {
			return err
		}
		// http.Client ignores errors while it discards a redirect body, so a
		// stalled one would be silently skipped. Read it here, like urllib
		// does in module_catalog.py, so a stall fails the download.
		if _, err := io.CopyN(io.Discard, req.Response.Body, 64<<10); err != nil && err != io.EOF {
			return reject("Module catalog download failed. Check the internet connection and try again.")
		}
		return nil
	}}
	failed := func() error {
		// Caller cancellation is not a network failure: report it as such.
		if err := ctx.Err(); err != nil {
			return err
		}
		return reject("Module catalog download failed. Check the internet connection and try again.")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, failed()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, reject("Module catalog download failed. Check the internet connection and try again.")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, failed()
	}
	if int64(len(b)) > limit {
		return nil, reject("Module download exceeds size limit")
	}
	return b, nil
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
