package main

import (
	"fmt"
	"os"
	"strings"

	// Load provider auth Specs (registered in each extension's init).
	_ "github.com/yeeth-security/scintx/extensions/providers/all"

	"github.com/yeeth-security/scintx/credentials"
	"golang.org/x/term"
)

// runAuth handles: scintx auth … (provider credentials for outbound APIs).
func runAuth(args []string) int {
	if len(args) == 0 {
		printAuthUsage()
		return 2
	}
	switch args[0] {
	case "status":
		return authStatus(args[1:])
	case "logout":
		return authLogout(args[1:])
	case "help", "-h", "--help":
		printAuthUsage()
		return 0
	default:
		spec, ok := credentials.Lookup(args[0])
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown auth provider %q\n", args[0])
			printAuthUsage()
			return 2
		}
		return authLogin(spec, args[1:])
	}
}

func printAuthUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  scintx auth <provider> [--token TOKEN] [--user USER]
      Store credentials for a provider (OS keyring, else credentials file).
      Prefer this over putting secrets in a .env file.

  scintx auth status
      Show where credentials are resolved from (never prints secrets).

  scintx auth logout <provider>
      Remove stored credentials (env vars are not changed).

Providers:`)
	specs := credentials.Specs()
	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "  (none registered — import provider extensions)")
		return
	}
	for _, s := range specs {
		line := "  " + s.ID
		if s.Summary != "" {
			line += " — " + s.Summary
		}
		fmt.Fprintln(os.Stderr, line)
		if s.HelpURL != "" {
			fmt.Fprintf(os.Stderr, "      %s\n", s.HelpURL)
		}
	}
}

func authLogin(spec credentials.Spec, args []string) int {
	token, user, err := parseAuthFlags(args, spec.UserEnv != "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	if token == "" {
		if spec.HelpURL != "" {
			fmt.Fprintf(os.Stderr, "Create a credential at %s\n", spec.HelpURL)
		}
		fmt.Fprint(os.Stderr, "Paste token (input hidden): ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read token: %v\n", err)
			return 1
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "empty token; nothing stored")
		return 1
	}

	src, err := credentials.Set(spec.ID, credentials.ProviderCreds{
		Token: token,
		User:  user,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to store credentials: %v\n", err)
		return 1
	}
	switch src {
	case credentials.SourceKeyring:
		fmt.Printf("%s credentials stored in OS keyring\n", spec.ID)
	case credentials.SourceFile:
		path, _ := credentials.CredentialsPath()
		fmt.Printf("%s credentials stored in %s (keyring unavailable)\n", spec.ID, path)
	default:
		fmt.Printf("%s credentials stored (%s)\n", spec.ID, src)
	}
	fmt.Printf("Restart scintx (or reload providers) so %s picks them up.\n", spec.ID)
	return 0
}

func parseAuthFlags(args []string, allowUser bool) (token, user string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token":
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("--token requires a value")
			}
			i++
			token = args[i]
		case "--user":
			if !allowUser {
				return "", "", fmt.Errorf("--user is not supported for this provider")
			}
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("--user requires a value")
			}
			i++
			user = args[i]
		default:
			return "", "", fmt.Errorf("unknown flag %q", args[i])
		}
	}
	return token, user, nil
}

func authStatus(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: scintx auth status")
		return 2
	}
	specs := credentials.Specs()
	if len(specs) == 0 {
		fmt.Println("no auth-capable providers registered")
		return 0
	}
	for _, s := range specs {
		r, err := credentials.Get(s.ID)
		if err != nil {
			fmt.Printf("%s: %v\n", s.ID, err)
			continue
		}
		if r.Source == credentials.SourceNone || r.Creds.Token == "" {
			fmt.Printf("%s: not configured (run: scintx auth %s)\n", s.ID, s.ID)
			continue
		}
		extra := ""
		if s.UserEnv != "" {
			user := r.Creds.User
			if user == "" {
				user = "(default)"
			}
			extra = fmt.Sprintf(" (user=%s)", user)
		}
		fmt.Printf("%s: configured via %s%s\n", s.ID, r.Source, extra)
	}
	return 0
}

func authLogout(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: scintx auth logout <provider>")
		return 2
	}
	provider := args[0]
	if !credentials.Known(provider) {
		fmt.Fprintf(os.Stderr, "unknown auth provider %q\n", provider)
		return 2
	}
	if err := credentials.Clear(provider); err != nil {
		fmt.Fprintf(os.Stderr, "logout failed: %v\n", err)
		return 1
	}
	fmt.Printf("%s credentials removed from keyring/file (env vars unchanged)\n", provider)
	return 0
}
