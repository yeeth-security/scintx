# SCINTX Extensions

SCINTX uses a **registry + auto-discovery** pattern. Extensions register themselves via `init()` when imported, and a code generator (`cmd/gen-extensions`) scans the extension directories and regenerates aggregation files that import every extension. **Adding a new extension requires no wiring changes** — just create the package and run `go generate`.

## Directory structure

```
extensions/
├── providers/              # Security-scanner provider adapters
│   ├── stub-osv/           # Stub OSV-style vulnerability provider
│   ├── stub-secrets/       # Stub secrets-detection provider
│   └── all/                # AUTO-GENERATED — imports every provider
│       └── all.go          # DO NOT EDIT — run `go generate ./extensions/...`
├── policies/               # Consumer-side policy engines
│   ├── default/            # Reference allow/review/deny/defer policy
│   └── all/                # AUTO-GENERATED — imports every policy
│       └── all.go
├── registries/             # Registry connectors (submission sources)
│   └── all/                # AUTO-GENERATED — imports every registry connector
│       └── all.go
└── extensions.go           # go:generate entry point
```

## Three extension interfaces

### 1. Provider (`scintx.Provider`)

A security-scanner adapter that assesses an artifact and returns findings.

```go
type Provider interface {
    ID() string
    Capabilities() ProviderCapabilities
    Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}
```

### 2. RegistryConnector (`scintx.RegistryConnector`)

A package-registry connector that acts as a submission source (e.g., polling a registry for new packages).

```go
type RegistryConnector interface {
    ID() string
    Manifest() RegistryManifest
}
```

### 3. PolicyEngine (`scintx.PolicyEngine`)

A consumer-side policy engine that maps provider results to a policy decision.

```go
type PolicyEngine interface {
    ID() string
    Evaluate(sub *Submission, results []*ProviderResult) (*PolicyDecision, error)
}
```

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
    "github.com/yeeth-security/scintx/internal/scintx"
)

type Provider struct{}

func init() {
    scintx.RegisterProviderFactory("my-scanner", func() (scintx.Provider, error) {
        return &Provider{}, nil
    })
}

func (p *Provider) ID() string { return "my-scanner" }

func (p *Provider) Capabilities() scintx.ProviderCapabilities {
    return scintx.ProviderCapabilities{
        SchemaVersion: "1.0.0",
        Provider:      scintx.ProviderRef{ID: "my-scanner", Version: "1.0"},
        // ...
        Capabilities: []scintx.Capability{
            {
                ID:      "malware",
                Version: "v1",
                InputProfiles: []scintx.InputProfile{
                    {
                        ID: "content-required",
                        Requires: []scintx.Requirement{
                            {Kind: scintx.ReqContent},
                            {Kind: scintx.ReqDigest, Algorithms: []string{"sha256"}},
                        },
                    },
                },
                FindingTypes: []string{"malware"},
            },
        },
    }
}

func (p *Provider) Assess(ctx context.Context, artifact scintx.Artifact, capability scintx.Capability) (*scintx.ProviderResult, error) {
    // ... your scanning logic ...
    return &scintx.ProviderResult{
        Execution: scintx.Execution{Status: scintx.ExecutionCompleted, /* ... */},
        Verdict:   &scintx.Verdict{Value: scintx.VerdictPass, Origin: scintx.VerdictOriginProvider},
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

import "github.com/yeeth-security/scintx/internal/scintx"

type MyPolicy struct{}

func init() {
    scintx.RegisterPolicyEngineFactory("my-policy", func() (scintx.PolicyEngine, error) {
        return &MyPolicy{}, nil
    })
}

func (p *MyPolicy) ID() string { return "my-policy" }

func (p *MyPolicy) Evaluate(sub *scintx.Submission, results []*scintx.ProviderResult) (*scintx.PolicyDecision, error) {
    // ... your policy logic ...
}
```

2. Run `go generate ./extensions/...`
3. Update `cmd/scintx/main.go` to load your policy: `scintx.LoadPolicyEngine("my-policy")`

## How to add a new registry connector

1. Create `extensions/registries/<your-registry>/connector.go`:

```go
package myregistry

import "github.com/yeeth-security/scintx/internal/scintx"

type Connector struct{}

func init() {
    scintx.RegisterRegistryConnectorFactory("my-registry", func() (scintx.RegistryConnector, error) {
        return &Connector{}, nil
    })
}

func (c *Connector) ID() string { return "my-registry" }

func (c *Connector) Manifest() scintx.RegistryManifest {
    return scintx.RegistryManifest{ID: "my-registry", Name: "My Registry", Version: "1.0"}
}
```

2. Run `go generate ./extensions/...`

## How auto-discovery works

1. Each extension package has an `init()` that calls `scintx.Register*Factory("id", factory)`.
2. `extensions/providers/all/all.go` (auto-generated) blank-imports every provider package, causing their `init()` to run.
3. `cmd/gen-extensions` scans `extensions/{providers,policies,registries}/` for directories containing `.go` files and regenerates the `all.go` files.
4. At startup, `orchestrator.LoadProvidersFromRegistry()` calls `scintx.LoadProviders()` which instantiates every registered factory.
5. `go generate ./extensions/...` is the only command needed after adding an extension.

## Duplicate IDs

Registering two extensions with the same ID panics at startup. This is intentional — it catches configuration errors early.

## Naming conventions

- Provider directory: `extensions/providers/<vendor-name>/` (kebab-case)
- Policy directory: `extensions/policies/<policy-name>/` (kebab-case)
- Registry directory: `extensions/registries/<registry-name>/` (kebab-case)
- Factory ID: should match the directory name

## Reference implementations

| Extension | Location | Interface |
|---|---|---|
| stub-osv | `extensions/providers/stub-osv/` | Provider |
| stub-secrets | `extensions/providers/stub-secrets/` | Provider |
| default | `extensions/policies/default/` | PolicyEngine |