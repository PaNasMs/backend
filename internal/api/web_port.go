package api

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var webHostname = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func healthConnectSource(host string) string {
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.User != nil {
		return ""
	}
	name := parsed.Hostname()
	if name == "" || (!webHostname.MatchString(name) && net.ParseIP(name) == nil) {
		return ""
	}
	return " http://" + net.JoinHostPort(name, "*") + "/api/v1/health"
}

func allowHealthProbe(w http.ResponseWriter, r *http.Request) {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || (origin.Scheme != "http" && origin.Scheme != "https") {
		return
	}
	host, err := url.Parse("http://" + r.Host)
	if err == nil && origin.Hostname() != "" && strings.EqualFold(origin.Hostname(), host.Hostname()) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Vary", "Origin")
	}
}
