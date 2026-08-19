package ossindex

import "github.com/yeeth-security/scintx/credentials"

// Auth Spec lives with the extension — env names, help URL, CLI summary.
// The shared credentials package only stores/resolves; it does not hardcode providers.
func init() {
	credentials.Register(credentials.Spec{
		ID:       providerID,
		TokenEnv: "SCINTX_OSSINDEX_TOKEN",
		UserEnv:  "SCINTX_OSSINDEX_USER",
		HelpURL:  "https://guide.sonatype.com",
		Summary:  "Sonatype Guide PAT for OSS Index (required)",
	})
}
