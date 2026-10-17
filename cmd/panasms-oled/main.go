package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"panasms.local/backend/internal/oled"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Administrator permissions required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	switch {
	case len(os.Args) == 1:
		err = oled.Run(ctx)
	case len(os.Args) == 2 && os.Args[1] == "configure":
		err = oled.Configure(ctx, os.Stdin)
	case len(os.Args) == 2 && os.Args[1] == "restore":
		err = oled.Restore(ctx)
	default:
		err = fmt.Errorf("usage: panasms-oled [configure|restore]")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
