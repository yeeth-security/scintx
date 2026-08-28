# SCINTX Extensions

SCINTX uses a **registry + auto-discovery** pattern. Extensions register themselves via `init()` when imported, and a code generator (`cmd/gen-extensions`) scans the extension directories and regenerates aggregation files that import every extension. **Adding a new extension requires no wiring changes** — just create the package and run `go generate`.

## Public contract

Extensions **must** import `github.com/yeeth-security/scintx/api` — never `internal/` packages.
The `api` package holds domain types, plugin interfaces, and `Register*Factory` helpers.
Outbound secrets use `github.com/yeeth-security/scintx/credentials` (keyring / file / env).
Provider-specific auth (env var names, help URL) is registered from the extension via
`credentials.Register(credentials.Spec{...})` in `init()` — see `ossindex/auth.go`.

## Directory structure

```
extensions/
├── providers/              # Security-scanner provider adapters
│   ├── osv/                # Real OSV.dev vulnerability provider (HTTP API)
│   ├── ossindex/           # Real Sonatype OSS Index vulnerability provider
│   ├── stub-osv/           # Offline stub for deterministic e2e / demos
│   ├── stub-secrets/       # Stub secrets-detection provider
│   └── all/                # AUTO-GENERATED — imports every provider
│       └── all.go          # DO NOT EDIT — run `go generate ./extensions/...`
├── policies/               # Consumer-side policy engines
│   ├── example/            # Hard-coded example allow/review/deny/defer policy
│   ├── yaml/               # YAML document-driven policy engine
│   └── all/                # AUTO-GENERATED — imports every policy
│       └── all.go
└── extensions.go           # go:generate entry point
```

## Two extension interfaces

### 1. Provider (`api.Provider`)

A security-scanner adapter that assesses an artifact and returns findings.

```go
type Provider interface {
    ID() string
    Capabilities() ProviderCapabilities
    Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}
```

Optional adjudication feedback (off unless listed in `SCINTX_FORWARD_ADJUDICATIONS`):

```go
type AdjudicationReceiver interface {
    ReceiveAdjudication(ctx context.Context, feedback AdjudicationFeedback) error
}
```

Also set `ProviderCapabilities.AcceptsAdjudications = true`. Feedback is anonymous: `decision` + `purl` only.

### 2. PolicyEngine (`api.PolicyEngine`)

A consumer-side policy engine that maps provider results to a policy decision.

```go
type PolicyEngine interface {
    ID() string
    Evaluate(sub *Submission, results []*ProviderResult) (*PolicyDecision, error)
}
```

Submission sources (package registries, CI, [package-feeds](https://github.com/ossf/package-feeds) bridges)
call `POST /v1/submissions` over HTTP. They are not in-process extensions.
## How to add a new provider

1. **Create a directory** under `extensions/providers/<your-provider>/`:

```
extensions/providers/my-scanner/
└── provider.go
```

2. **Write the provider** with an `init()` that registers a factory:

```go
package myscanner

import (
    "context"
    "github.com/yeeth-security/scintx/api"
)

type Provider struct{}

func init() {
    api.RegisterProviderFactory("my-scanner", func() (api.Provider, error) {
        return &Provider{}, nil
    })
}

func (p *Provider) ID() string { return "my-scanner" }

func (p *Provider) Capabilities() api.ProviderCapabilities {
    return api.ProviderCapabilities{
        SchemaVersion: "1.0.0",
        Provider:      api.ProviderRef{ID: "my-scanner", Version: "1.0"},
        Capabilities: []api.Capability{
            {
                ID:      "malware",
                Version: "v1",
                InputProfiles: []api.InputProfile{
                    {
                        ID: "content-required",
                        Requires: []api.Requirement{
                            {Kind: api.ReqContent},
                            {Kind: api.ReqDigest, Algorithms: []string{"sha256"}},
                        },
                    },
                },
                FindingTypes: []string{"malware"},
            },
        },
    }
}

func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
    return &api.ProviderResult{
        Execution: api.Execution{Status: api.ExecutionCompleted},
        Verdict:   &api.Verdict{Value: api.VerdictPass, Origin: api.VerdictOriginProvider},
    }, nil
}
```

3. **Regenerate the aggregation files:**

```bash
go generate ./extensions/...
```

4. **Build and run.** The provider is automatically picked up — no wiring changes needed.

## How to add a new policy engine

1. Create `extensions/policies/<your-policy>/policy.go`:

```go
package mypolicy

import "github.com/yeeth-security/scintx/api"

type MyPolicy struct{}

func init() {
    api.RegisterPolicyEngineFactory("my-policy", func() (api.PolicyEngine, error) {
        return &MyPolicy{}, nil
    })
}

func (p *MyPolicy) ID() string { return "my-policy" }

func (p *MyPolicy) Evaluate(sub *api.Submission, results []*api.ProviderResult) (*api.PolicyDecision, error) {
    // ... your policy logic ...
}
```

2. Run `go generate ./extensions/...`
3. Update `cmd/scintx/main.go` to load your policy: `api.LoadPolicyEngine("my-policy")`

## How auto-discovery works

1. Each extension package has an `init()` that calls `api.Register*Factory("id", factory)`.
2. `extensions/providers/all/all.go` (auto-generated) blank-imports every provider package, causing their `init()` to run.
3. `cmd/gen-extensions` scans `extensions/{providers,policies}/` for directories containing `.go` files and regenerates the `all.go` files.
4. At startup, `orchestrator.LoadProvidersFromRegistry()` calls `api.LoadProviders()` which instantiates every registered factory (sorted by ID).
5. `go generate ./extensions/...` is the only command needed after adding an extension.

## Duplicate IDs

Registering two extensions with the same ID panics at startup. This is intentional — it catches configuration errors early.

## Naming conventions

- Provider directory: `extensions/providers/<vendor-name>/` (kebab-case)
- Policy directory: `extensions/policies/<policy-name>/` (kebab-case)
- Factory ID: should match the directory name

## Reference implementations

| Extension | Location | Interface |
|---|---|---|
| osv | `extensions/providers/osv/` | Provider (live OSV.dev; `SCINTX_OSV_BASE_URL`; optional `SCINTX_OSV_BEARER_TOKEN` / `SCINTX_OSV_API_KEY`) |
| ossindex | `extensions/providers/ossindex/` | Provider (Sonatype OSS Index / Guide; `SCINTX_OSSINDEX_TOKEN`) |
| argus | `extensions/providers/argus/` | Provider (malware scan of VSIX bytes; `ARGUS_API_KEY`, `ARGUS_BASE_URL`, `ARGUS_SCAN_TIMEOUT`) |
| stub-osv | `test/stubs/stubosv/` | Provider (offline test fixture; not in the production binary) |
| stub-secrets | `test/stubs/secretsstub/` | Provider (offline test fixture; not in the production binary) |
| example | `extensions/policies/example/` | PolicyEngine (hard-coded example thresholds) |
| yaml | `extensions/policies/yaml/` | PolicyEngine (YAML documents in `policies/`) |

Optional startup filter: `SCINTX_PROVIDERS=osv,ossindex,argus` (comma-separated). Empty loads every registered production factory; missing-cred providers skip cleanly. The default production set is osv + ossindex + argus (`malware-bazaar` tracked in SCINTX-110, not built yet). E2E imports the offline stubs from `test/stubs/` so vulnerability assessments stay offline.
## YAML policies

The `yaml` policy engine loads every `*.yaml` / `*.yml` file from `SCINTX_POLICIES_DIR`
(default: `./policies`). A submission’s `policy_ref` must match a document’s `metadata.id`.

```yaml
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: registry-default      # ← policy_ref value
  version: "1"
spec:
  on_timeout: review
  on_error: review
  on_missing_verdict: review
  verdicts:
    pass: allow
    warn: review
    fail: review
    unknown: defer
  findings:
    - when:
        assessment: affected
        severity_scheme: CVSS
        min_score: 9.0
      decision: deny
      reason_code: critical_severity_vulnerability
      message: "CVSS {{score}} vulnerability with no fix available"
  defer:
    resume_after: 1h
```

Message placeholders: `{{score}}`, `{{finding_id}}`, `{{result_id}}`.

Start the gateway with the YAML engine (default):

```bash
SCINTX_POLICIES_DIR=./policies ./bin/scintx
# or: SCINTX_POLICY_ENGINE=example ./bin/scintx   # hard-coded example engine
```

