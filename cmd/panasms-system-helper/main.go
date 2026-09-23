// Command panasms-system-helper is the Go system-operation execution process.
// The privileged agent invokes it (through the host mount namespace) as:
//
//	panasms-system-helper <mode> <user>
//
// with the JSON request on stdin, the bounded JSON result on stdout, progress
// and cancellation-capability messages as newline-delimited JSON on stderr, and
// a cancellation pipe on the descriptor named by PANASMS_CONTROL_FD.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/webaccess"
	"panasms.local/backend/internal/systemops/worker"

	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/systemops"
)

func main() {
	// `routes` emits the explicit Go/legacy routing inventory as JSON for the
	// API contract test and for audit. It touches no host state.
	if len(os.Args) == 2 && os.Args[1] == "routes" {
		if err := json.NewEncoder(os.Stdout).Encode(management.RouteInventory()); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "check-admin" {
		if err := accounts.CheckAdmin(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "web-access" {
		if os.Geteuid() != 0 {
			os.Exit(1)
		}
		flags := flag.NewFlagSet("web-access", flag.ExitOnError)
		apply := flags.Bool("apply", false, "")
		recover := flags.Bool("recover", false, "")
		configure := flags.Bool("configure", false, "")
		current := flags.Bool("current", false, "")
		port := flags.Int("port", 0, "")
		flags.Parse(os.Args[2:])
		count := 0
		for _, selected := range []bool{*apply, *recover, *configure, *current} {
			if selected {
				count++
			}
		}
		if count != 1 || flags.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "select one web-access operation")
			os.Exit(2)
		}
		s := webaccess.Default()
		var err error
		switch {
		case *current:
			var n int
			n, err = s.Current()
			if err == nil {
				fmt.Println(n)
			}
		case *apply && !*recover && !*configure:
			err = s.Apply()
		case *recover && !*apply && !*configure:
			err = s.Recover()
		case *configure && !*apply && !*recover:
			var value any
			flags.Visit(func(f *flag.Flag) {
				if f.Name == "port" {
					value = *port
				}
			})
			var n int
			n, err = s.Configure(value)
			if err == nil {
				fmt.Println(n)
			}
		default:
			err = fmt.Errorf("select one web-access operation")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: panasms-system-helper <mode> <user> | panasms-system-helper routes")
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Administrator permissions required")
		os.Exit(1)
	}
	mode := systemops.Mode(os.Args[1])
	user := os.Args[2]

	reporter := systemops.NewReporter(os.Stderr, systemops.Env)
	defer reporter.Close()

	if err := systemops.Run(mode, user, os.Stdin, os.Stdout, reporter, worker.New().Handle); err != nil {
		fmt.Fprintln(os.Stderr, "helper I/O failure")
		os.Exit(1)
	}
}
