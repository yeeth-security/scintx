package scintx

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

type adjRecvProvider struct {
	id       string
	accepts  bool
	mu       sync.Mutex
	received []api.AdjudicationFeedback
}

func (p *adjRecvProvider) ID() string { return p.id }
func (p *adjRecvProvider) Capabilities() api.ProviderCapabilities {
	return api.ProviderCapabilities{
		Provider:             api.ProviderRef{ID: p.id},
		AcceptsAdjudications: p.accepts,
	}
}
func (p *adjRecvProvider) Assess(context.Context, api.Artifact, api.Capability) (*api.ProviderResult, error) {
	return nil, nil
}
func (p *adjRecvProvider) ReceiveAdjudication(_ context.Context, fb api.AdjudicationFeedback) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.received = append(p.received, fb)
	return nil
}

type adjNoRecvProvider struct {
	id string
}

func (p *adjNoRecvProvider) ID() string { return p.id }
func (p *adjNoRecvProvider) Capabilities() api.ProviderCapabilities {
	return api.ProviderCapabilities{
		Provider:             api.ProviderRef{ID: p.id},
		AcceptsAdjudications: true,
	}
}
func (p *adjNoRecvProvider) Assess(context.Context, api.Artifact, api.Capability) (*api.ProviderResult, error) {
	return nil, nil
}

func TestParseAllowlist(t *testing.T) {
	if parseAllowlist("") != nil || parseAllowlist("  ") != nil {
		t.Fatal("empty should be nil")
	}
	got := parseAllowlist("osv, ossindex ,")
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["osv"]; !ok {
		t.Fatal("missing osv")
	}
	if _, ok := got["ossindex"]; !ok {
		t.Fatal("missing ossindex")
	}
}

func TestAdjudicationForwardTargets(t *testing.T) {
	recv := &adjRecvProvider{id: "osv", accepts: true}
	noFlag := &adjRecvProvider{id: "ossindex", accepts: false}
	noIface := &adjNoRecvProvider{id: "stub"}
	notListed := &adjRecvProvider{id: "other", accepts: true}

	o := NewOrchestrator(NewMemoryStore(), nil, NewEventEmitter("test", NewMemoryStore()),
		WithAdjudicationForwarding(map[string]struct{}{"osv": {}, "ossindex": {}, "stub": {}}),
	)
	o.providers = []api.Provider{recv, noFlag, noIface, notListed}

	targets := o.adjudicationForwardTargets()
	if len(targets) != 1 || targets[0].ID() != "osv" {
		ids := make([]string, len(targets))
		for i, p := range targets {
			ids[i] = p.ID()
		}
		t.Fatalf("targets=%v", ids)
	}
}

func TestForwardAdjudicationBestEffort(t *testing.T) {
	recv := &adjRecvProvider{id: "osv", accepts: true}
	o := NewOrchestrator(NewMemoryStore(), nil, NewEventEmitter("test", NewMemoryStore()),
		WithAdjudicationForwarding(map[string]struct{}{"osv": {}}),
	)
	o.providers = []api.Provider{recv}

	purl := "pkg:npm/left-pad@1.3.0"
	sub := &api.Submission{ID: "sub_1", Artifact: api.Artifact{PURL: &purl}}
	o.forwardAdjudicationBestEffort(sub, api.DecisionAllow)

	deadline := time.Now().Add(2 * time.Second)
	for {
		recv.mu.Lock()
		n := len(recv.received)
		recv.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for forward")
		}
		time.Sleep(10 * time.Millisecond)
	}

	recv.mu.Lock()
	fb := recv.received[0]
	recv.mu.Unlock()
	if fb.Decision != api.DecisionAllow || fb.PURL != purl {
		t.Fatalf("feedback=%+v", fb)
	}
}

func TestForwardAdjudicationOffByDefault(t *testing.T) {
	recv := &adjRecvProvider{id: "osv", accepts: true}
	o := NewOrchestrator(NewMemoryStore(), nil, NewEventEmitter("test", NewMemoryStore()))
	o.providers = []api.Provider{recv}
	purl := "pkg:npm/x@1"
	o.forwardAdjudicationBestEffort(&api.Submission{Artifact: api.Artifact{PURL: &purl}}, api.DecisionDeny)
	time.Sleep(50 * time.Millisecond)
	recv.mu.Lock()
	defer recv.mu.Unlock()
	if len(recv.received) != 0 {
		t.Fatalf("expected no forward when allowlist empty, got %v", recv.received)
	}
}
