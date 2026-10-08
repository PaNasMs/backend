package networkaccess

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortalOnlyOwnDirectNetworks(t *testing.T) {
	rows := []Device{
		{Name: "usb0", Profile: usbUUID, Connected: true, Addresses: []string{"10.180.120.2/32", "10.180.120.1/24"}},
		{Name: "wlan0", Profile: apUUID, Connected: true, Addresses: []string{"10.180.10.1/24"}},
		{Name: "end0", Connected: true, Addresses: []string{"192.168.1.1/24"}},
		{Name: "wlan1", Profile: "user-ap", Connected: true, Addresses: []string{"10.42.0.1/24"}},
		{Name: "usb1", Profile: usbUUID, Connected: true, Reserved: true, Addresses: []string{"10.180.121.1/24"}},
	}
	got := portalEndpoints(Config{USB: true, Enabled: true}, rows)
	if len(got) != 2 || got[0].Alias != "10.180.120.2" || got[1].Interface != "wlan0" {
		t.Fatalf("%+v", got)
	}
	if got := portalEndpoints(Config{}, rows); len(got) != 0 {
		t.Fatalf("Disabled: %+v", got)
	}
}

func TestPortalRedirectCanonicalAndCurrentPort(t *testing.T) {
	port := 80
	h := portalHandler("10.180.120.1", func() (int, error) { return port, nil })
	for _, p := range []int{80, 8088} {
		port = p
		req := httptest.NewRequest("GET", "http://attacker.example/generate_204?redirect=https://evil.test", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := "http://10.180.120.1/"
		if p == 8088 {
			want = "http://10.180.120.1:8088/"
		}
		if w.Code != 302 || w.Header().Get("Location") != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v", w.Code, w.Header())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://probe/", strings.NewReader("password=secret")))
	if w.Code != 405 || w.Header().Get("Location") != "" {
		t.Fatal(w)
	}
	w = httptest.NewRecorder()
	portalHandler("10.180.120.1", func() (int, error) { return 0, errors.New("bad config") }).ServeHTTP(w, httptest.NewRequest("GET", "http://probe/", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestPortalRulesDoNotInterceptLANPanelOrHTTPS(t *testing.T) {
	rules := portalRules(map[string]*portalInstance{"usb0": {endpoint: portalEndpoint{"usb0", "10.180.120.1", "10.180.120.2"}, httpPort: 32001, dnsPort: 32002}})
	for _, want := range []string{`iifname "usb0" ip daddr 10.180.120.1 udp dport 53`, `iifname "usb0" ip daddr 10.180.120.1 tcp dport 53`, `iifname "usb0" ip daddr 10.180.120.2 tcp dport 80 dnat to 10.180.120.2:32001`} {
		if !strings.Contains(rules, want) {
			t.Fatal(rules)
		}
	}
	for _, bad := range []string{"dport 443", "ip daddr 10.180.120.1 tcp dport 80", "forward", "masquerade", "end0"} {
		if strings.Contains(rules, bad) {
			t.Fatal(rules)
		}
	}
	args := strings.Join(portalDNSArgs(portalEndpoint{"usb0", "10.180.120.1", "10.180.120.2"}, 32002), " ")
	if strings.Contains(args, "dhcp-range") || strings.Contains(args, "address=/#/") || !strings.Contains(args, "--address=/networkcheck.kde.org/10.180.120.2") {
		t.Fatal(args)
	}
}
