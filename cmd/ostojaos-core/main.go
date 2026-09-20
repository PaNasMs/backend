package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"ostojaos.local/backend/internal/api"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/store"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "listen address")
	db := flag.String("db", "/var/lib/ostojaos/state.db", "SQLite file")
	static := flag.String("static", "/usr/share/ostojaos/ui", "SPA assets")
	socket := flag.String("agent", "/run/ostojaos-agent/agent.sock", "agent socket")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	allowHTTP := flag.Bool("allow-http", false, "allow unencrypted HTTP outside loopback")
	flag.Parse()
	secure := *cert != "" && *key != ""
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	if !secure && !*allowHTTP && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		log.Fatal("TLS required outside loopback")
	}
	allowed, policyErr := auth.AccessPolicy(os.Getenv("OSTOJAOS_AUTH_MODE"), os.Getenv("OSTOJAOS_ALLOWED_USERS"))
	if policyErr != nil {
		log.Fatal(policyErr)
	}

	data, err := store.Open(*db)
	if err != nil {
		log.Fatal(err)
	}
	defer data.Close()
	s := api.New(data, *socket, *static, allowed, secure)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go s.Run(ctx)
	srv := &http.Server{Addr: *addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 0, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	log.Printf("OstojaOS core listening on %s (TLS=%t)", *addr, secure)
	if secure {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
