package api

import (
	"context"
	"errors"
	"testing"
)

func TestSkipProvider(t *testing.T) {
	want := "ossindex skipped: run 'scintx auth ossindex' or set SCINTX_OSSINDEX_TOKEN for CI (https://guide.sonatype.com)"
	err := SkipProvider(want)
	if !errors.Is(err, ErrProviderSkipped) {
		t.Fatalf("want ErrProviderSkipped, got %v", err)
	}
	if err.Error() != want {
		t.Fatalf("message=%q", err.Error())
	}
}

func TestLoadProviders_SkipsOptional(t *testing.T) {
	// Register a throwaway factory that always skips, then load with an allowlist
	// that only includes it plus a keep factory for this test.
	const skipID = "test-skip-provider"
	const keepID = "test-keep-provider"

	RegisterProviderFactory(skipID, func() (Provider, error) {
		return nil, SkipProvider(skipID + " skipped: run 'scintx auth ossindex' or set SCINTX_OSSINDEX_TOKEN for CI (https://guide.sonatype.com)")
	})
	RegisterProviderFactory(keepID, func() (Provider, error) {
		return &stubProvider{id: keepID}, nil
	})

	t.Setenv("SCINTX_PROVIDERS", skipID+","+keepID)
	providers, err := LoadProviders()
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].ID() != keepID {
		ids := make([]string, len(providers))
		for i, p := range providers {
			ids[i] = p.ID()
		}
		t.Fatalf("providers=%v", ids)
	}
}

type stubProvider struct{ id string }

func (s *stubProvider) ID() string { return s.id }
func (s *stubProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{Provider: ProviderRef{ID: s.id}}
}
func (s *stubProvider) Assess(_ context.Context, _ Artifact, _ Capability) (*ProviderResult, error) {
	return nil, nil
}
