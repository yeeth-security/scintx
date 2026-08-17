package scintx

import "context"

type Provider interface {
	ID() string
	Capabilities() ProviderCapabilities
	Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}