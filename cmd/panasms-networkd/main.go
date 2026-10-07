package main

import (
	"fmt"
	"os"
	"panasms.local/backend/internal/systemops/networkd"
)

func main() {
	if os.Geteuid() != 0 || len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Run as administrator and select a network operation")
		os.Exit(1)
	}
	if err := networkd.Run(os.Args[1], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
