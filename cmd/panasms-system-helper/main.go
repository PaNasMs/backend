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
	"os/exec"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/networkaccess"
	"panasms.local/backend/internal/systemops/networknative"
	"panasms.local/backend/internal/systemops/volumeaccess"
	"panasms.local/backend/internal/systemops/webaccess"
	"panasms.local/backend/internal/systemops/worker"

	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/systemops"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "disk-sleep" {
		if os.Geteuid() != 0 {
			os.Exit(1)
		}
		if err := disksleep.Command(os.Args[2], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) >= 3 && os.Args[1] == "volume-access" {
		if os.Geteuid() != 0 {
			os.Exit(1)
		}
		var err error
		switch {
		case len(os.Args) == 3 && os.Args[2] == "run":
			err = volumeaccess.Run(false)
		case len(os.Args) == 3 && os.Args[2] == "once":
			err = volumeaccess.Run(true)
		case len(os.Args) == 4 && os.Args[2] == "apply":
			err = volumeaccess.ApplyMounted(os.Args[3])
		default:
			err = fmt.Errorf("unknown volume access command")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && (os.Args[1] == "network-native" || os.Args[1] == "network-services") {
		if os.Geteuid() != 0 || (os.Args[2] != "run" && os.Args[2] != "recover") {
			os.Exit(1)
		}
		var e error
		nm := exec.Command("systemctl", "is-active", "--quiet", "NetworkManager").Run() == nil
		if os.Args[1] == "network-services" && nm {
			script, args := "network_sharing.py", []string{"--service"}
			if os.Args[2] == "recover" {
				script, args = "wifi.py", []string{"--recover"}
			}
			cmd := exec.Command("/usr/bin/python3", append([]string{"-B", "/usr/lib/panasms/management/" + script}, args...)...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			e = cmd.Run()
		} else {
			switch os.Args[2] {
			case "run":
				e = networknative.Service()
			case "recover":
				e = networknative.Recover(false)
			default:
				e = fmt.Errorf("Unknown native network command")
			}
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "network-access" {
		if os.Geteuid() != 0 {
			os.Exit(1)
		}
		var err error
		switch os.Args[2] {
		case "initialize":
			err = networkaccess.Initialize()
		case "credentials":
			err = networkaccess.Credentials()
		case "run":
			err = networkaccess.Run()
		case "remove":
			err = networkaccess.Remove()
		default:
			err = fmt.Errorf("unknown network access command")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

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
