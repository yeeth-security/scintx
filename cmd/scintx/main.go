package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		runServe()
		return
	}
	switch args[0] {
	case "serve":
		runServe()
	case "auth":
		os.Exit(runAuth(args[1:]))
	case "help", "-h", "--help":
		printRootUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		printRootUsage()
		os.Exit(2)
	}
}

func printRootUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  scintx              Start the HTTP gateway (same as: scintx serve)
  scintx serve        Start the HTTP gateway
  scintx auth …       Manage outbound provider credentials
  scintx help         Show this help

Run "scintx auth help" for credential commands.
`)
}
