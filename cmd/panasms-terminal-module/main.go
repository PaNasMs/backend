package main

import (
	"net/http"
	"panasms.local/backend/internal/modulehost"
)

func main() {
	modulehost.Serve("terminal", func(allowed map[string]bool) http.Handler { return terminalHandler(allowed) })
}
