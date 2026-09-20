package main

import (
	"net/http"
	"panasms.local/backend/internal/modulehost"
)

func main() {
	modulehost.Serve("files", func(allowed map[string]bool) http.Handler { return filesHandler(allowed) })
}
