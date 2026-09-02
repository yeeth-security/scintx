package osv

import "github.com/yeeth-security/scintx/credentials"

// Optional outbound auth for private OSV mirrors / API gateways.
// Public api.osv.dev usually needs no token.
func init() {
	credentials.Register(credentials.Spec{
		ID:       "osv",
		TokenEnv: "SCINTX_OSV_BEARER_TOKEN",
		HelpURL:  "https://google.github.io/osv.dev/",
		Summary:  "Optional OSV bearer token (private mirrors)",
	})
}
