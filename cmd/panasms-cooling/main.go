package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"panasms.local/backend/internal/coolingdaemon"
	"syscall"
)

func main() {
	var err error
	if len(os.Args) == 2 && os.Args[1] == "--failsafe" {
		err = coolingdaemon.Failsafe()
	} else if len(os.Args) == 2 && os.Args[1] == "--configure" {
		err = coolingdaemon.Configure()
	} else {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		err = coolingdaemon.Run(ctx)
	}
	if err != nil {
		log.Fatal(err)
	}
}
