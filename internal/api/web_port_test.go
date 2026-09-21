package api

import (
	"net/http/httptest"
	"testing"
)

func TestHealthProbeScope(t *testing.T) {
	for _, tt := range []struct {
		origin  string
		allowed bool
	}{
		{"http://192.168.1.100", true}, {"http://192.168.1.100:8080", true},
		{"https://attacker.test", false}, {"null", false}, {"http://user@192.168.1.100", false},
	} {
		r := httptest.NewRequest("GET", "http://192.168.1.100:8081/api/v1/health", nil)
		r.Header.Set("Origin", tt.origin)
		w := httptest.NewRecorder()
		allowHealthProbe(w, r)
		if (w.Header().Get("Access-Control-Allow-Origin") != "") != tt.allowed {
			t.Fatal(tt.origin)
		}
	}
	if healthConnectSource("[::1]:8080") != " http://[::1]:*/api/v1/health" {
		t.Fatal("IPv6 source")
	}
	if healthConnectSource("host;bad") != "" {
		t.Fatal("unsafe source")
	}
}
