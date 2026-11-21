package modulelifecycle

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func repositoryURL(raw string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(strings.SplitN(raw, "?", 2)[0]) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") || (!allowQuery && (u.ForceQuery || u.RawQuery != "")) || (u.Port() != "" && u.Port() != "443") {
		return nil, reject("Use an HTTPS repository URL without credentials, query or fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return nil, reject("Use a public HTTPS repository URL")
	}
	if addr, err := netip.ParseAddr(host); err == nil && !publicAddress(addr) {
		return nil, reject("Use a public HTTPS repository URL")
	}
	return u, nil
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
}

func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Zone() != "" {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// Resolve once and connect only to vetted addresses. Validate each redirect
// as well; signed GitHub asset redirects can carry a query string.
func dialRepository(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	for _, addr := range ips {
		if !publicAddress(addr) {
			continue
		}
		if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port)); err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("no public repository address available")
}

type downloadKind uint8

const (
	metadataDownload downloadKind = iota
	archiveDownload
)

type catalogDownload func(context.Context, string, int64, downloadKind) ([]byte, error)

func (kind downloadKind) timeout() time.Duration {
	if kind == archiveDownload {
		return 60 * time.Second
	}
	return 10 * time.Second
}

func newCatalogDownload() catalogDownload {
	transport := &http.Transport{DialContext: dialRepository, TLSHandshakeTimeout: 5 * time.Second, IdleConnTimeout: 10 * time.Second}
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return reject("Too many module download redirects")
		}
		_, err := repositoryURL(req.URL.String(), true)
		return err
	}}
	return downloadWithClient(client)
}

func downloadWithClient(client *http.Client) catalogDownload {
	return func(ctx context.Context, raw string, limit int64, kind downloadKind) ([]byte, error) {
		u, err := repositoryURL(raw, false)
		if err != nil {
			return nil, err
		}
		requestCtx, cancel := context.WithTimeout(ctx, kind.timeout())
		defer cancel()
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "PaNasMs/0.2")
		failure := func() error {
			if cause := context.Cause(ctx); cause != nil {
				return cause
			}
			if requestCtx.Err() == context.DeadlineExceeded {
				if kind == archiveDownload {
					return reject("Module archive download timed out")
				}
				return reject("Module repository metadata download timed out")
			}
			return reject("Module catalog download failed. Check the internet connection and try again.")
		}
		response, err := client.Do(req)
		if err != nil {
			return nil, failure()
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, failure()
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
		if err != nil {
			return nil, failure()
		}
		if int64(len(body)) > limit {
			return nil, reject("Module download exceeds size limit")
		}
		return body, nil
	}
}
