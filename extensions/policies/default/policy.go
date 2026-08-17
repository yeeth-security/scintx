// Package defaultpolicy is the reference policy engine.
//
// It is auto-registered via init() when imported. To enable it, import
// this package from extensions/policies/all/all.go (auto-generated).
//
// To add a new policy engine, create a new directory under extensions/policies/
// with an init() that calls scintx.RegisterPolicyEngineFactory("mypolicy", ...).
// Then run `go generate ./extensions/...` to pick it up automatically.
package defaultpolicy

import (
	"github.com/yeeth-security/scintx/internal/scintx"
)

func init() {
	scintx.RegisterPolicyEngineFactory("default", func() (scintx.PolicyEngine, error) {
		return &scintx.DefaultPolicyEngine{
			PolicyID:         "registry-default",
			Version:          "1",
			DenyAboveScore:   9.0,
			ReviewAboveScore: 7.0,
			TimeoutBehavior:  "review",
		}, nil
	})
}