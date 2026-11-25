package modulelifecycle

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// catalogTestTransfer routes the public catalog host to a local TLS server, so
// the transport is exercised with its URL and redirect checks unchanged.
func catalogTestTransfer(t *testing.T, handler http.HandlerFunc, timeout time.Duration) catalogTransfer {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().String()
	return catalogTransfer{
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		tls:     server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
		timeout: timeout,
	}
}

func TestCatalogDownloadSlowLiveTransferCompletes(t *testing.T) {
	const timeout = 300 * time.Millisecond
	chunk := bytes.Repeat([]byte("x"), 64)
	transfer := catalogTestTransfer(t, func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		// Twelve chunks at 100ms keep the connection busy for well over four
		// timeouts, while no single wait comes close to one.
		for range 12 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}, timeout)
	start := time.Now()
	raw, err := transfer.download(context.Background(), "https://example.com/catalog.json", 4096)
	if err != nil {
		t.Fatalf("slow but live download failed after %s: %v", time.Since(start), err)
	}
	if len(raw) != 12*len(chunk) {
		t.Fatalf("got %d bytes", len(raw))
	}
	if elapsed := time.Since(start); elapsed < 3*timeout {
		t.Fatalf("transfer finished in %s; the fixture no longer outlasts the timeout", elapsed)
	}
}

func TestCatalogDownloadStalledTransferFails(t *testing.T) {
	const timeout = 200 * time.Millisecond
	for name, partial := range map[string]bool{"before headers": false, "mid body": true} {
		t.Run(name, func(t *testing.T) {
			transfer := catalogTestTransfer(t, func(w http.ResponseWriter, r *http.Request) {
				if partial {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			}, timeout)
			start := time.Now()
			_, err := transfer.download(context.Background(), "https://example.com/catalog.json", 4096)
			elapsed := time.Since(start)
			if err == nil || !strings.Contains(err.Error(), "Module catalog download failed") {
				t.Fatalf("stalled download returned %v", err)
			}
			if elapsed < timeout || elapsed > 5*time.Second {
				t.Fatalf("stalled download failed after %s, want about %s", elapsed, timeout)
			}
		})
	}
}

// A redirect response whose body stalls must still fail after the
// per-operation timeout instead of hanging the catalog request.
func TestCatalogDownloadStalledRedirectBodyFails(t *testing.T) {
	const timeout = 200 * time.Millisecond
	transfer := catalogTestTransfer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/catalog.json" {
			w.Write([]byte("{}"))
			return
		}
		w.Header().Set("Location", "https://example.com/catalog.json")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(20 * time.Second):
		}
	}, timeout)
	done := make(chan error, 1)
	go func() {
		_, err := transfer.download(context.Background(), "https://example.com/redirect", 4096)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled redirect accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download still blocked 5s after a stalled redirect body (per-operation timeout 200ms)")
	}
}

func TestCatalogDownloadReportsCallerCancellation(t *testing.T) {
	transfer := catalogTestTransfer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, err := transfer.download(ctx, "https://example.com/catalog.json", 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled download returned %v, want context.Canceled", err)
	}
}

func TestCatalogDownloadKeepsPublicHTTPSRestrictions(t *testing.T) {
	transfer := catalogTestTransfer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/plain":
			http.Redirect(w, r, "http://example.com/catalog.json", http.StatusFound)
		case "/loopback":
			http.Redirect(w, r, "https://127.0.0.1/catalog.json", http.StatusFound)
		default:
			w.Write([]byte("{}"))
		}
	}, time.Second)
	for _, value := range []string{"http://example.com/catalog.json", "https://localhost/catalog.json", "https://127.0.0.1/catalog.json", "https://10.0.0.1/catalog.json", "https://example.com:8443/catalog.json", "https://example.com/plain", "https://example.com/loopback"} {
		if _, err := transfer.download(context.Background(), value, 4096); err == nil {
			t.Errorf("%s was accepted", value)
		}
	}
	if _, err := dialCatalog(context.Background(), "tcp", "localhost:443"); err == nil || !strings.Contains(err.Error(), "public HTTPS") {
		t.Fatalf("dialing a loopback name returned %v", err)
	}
	if _, err := transfer.download(context.Background(), "https://example.com/catalog.json", 4096); err != nil {
		t.Fatalf("fixture rejects a valid download: %v", err)
	}
}
