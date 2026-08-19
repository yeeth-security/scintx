package scintx

import (
	"context"
	"strings"
	"testing"

	"github.com/yeeth-security/scintx/api"
)

// contentProbeProvider records the Artifact.Content it received in Assess.
type contentProbeProvider struct {
	id  string
	got []byte
	cap api.Capability
}

func (p *contentProbeProvider) ID() string { return p.id }
func (p *contentProbeProvider) Capabilities() api.ProviderCapabilities {
	return api.ProviderCapabilities{
		Provider:     api.ProviderRef{ID: p.id},
		Capabilities: []api.Capability{p.cap},
	}
}
func (p *contentProbeProvider) Assess(_ context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	p.got = append([]byte(nil), artifact.Content...)
	return &api.ProviderResult{
		ID:        "res_probe",
		Execution: api.Execution{Status: api.ExecutionCompleted},
		Verdict:   &api.Verdict{Value: api.VerdictPass, Origin: api.VerdictOriginProvider},
	}, nil
}

type allowPolicy struct{}

func (allowPolicy) ID() string { return "allow" }
func (allowPolicy) Evaluate(sub *api.Submission, _ []*api.ProviderResult) (*api.PolicyDecision, error) {
	return &api.PolicyDecision{
		ID: "dec_allow", SubmissionID: sub.ID, Decision: api.DecisionAllow,
		Policy: api.PolicyRef{ID: "allow", Version: "1"}, EvaluatedAt: apiNow(),
	}, nil
}

func TestHydrateLocalBlob(t *testing.T) {
	st := NewMemoryStore()
	body := []byte("zip-or-bin")
	digest := "sha256:deadbeef"
	if err := st.PutArtifact(digest, body); err != nil {
		t.Fatal(err)
	}
	o := NewOrchestrator(st, nil, NewEventEmitter("test", st))
	art := &api.Artifact{
		ContentRef: &api.ResourceReference{URI: api.BlobURN(digest)},
	}
	if err := o.hydrateLocalBlob(art); err != nil {
		t.Fatal(err)
	}
	if string(art.Content) != string(body) {
		t.Fatalf("content=%q", art.Content)
	}
	art.Content[0] = 'X'
	again, _, _ := st.GetArtifact(digest)
	if again[0] == 'X' {
		t.Fatal("caller must not mutate stored bytes")
	}
}

func TestHydrateLocalBlobMissingFailsClosed(t *testing.T) {
	st := NewMemoryStore()
	o := NewOrchestrator(st, nil, NewEventEmitter("test", st))
	art := &api.Artifact{
		ContentRef: &api.ResourceReference{URI: api.BlobURN("sha256:missing")},
	}
	err := o.hydrateLocalBlob(art)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("want missing blob error, got %v", err)
	}
	if art.Content != nil {
		t.Fatal("Content must stay empty on miss")
	}
}

func TestHydrateSkipsExternalURI(t *testing.T) {
	st := NewMemoryStore()
	o := NewOrchestrator(st, nil, NewEventEmitter("test", st))
	art := &api.Artifact{
		ContentRef: &api.ResourceReference{URI: "https://files.example/a.bin"},
	}
	if err := o.hydrateLocalBlob(art); err != nil {
		t.Fatal(err)
	}
	if art.Content != nil {
		t.Fatal("must not fetch remote URLs")
	}
}

func TestProcessHydratesContentForAssess(t *testing.T) {
	st := NewMemoryStore()
	body := []byte("sample-bytes")
	digest := "sha256:" + strings.Repeat("ab", 32)
	if err := st.PutArtifact(digest, body); err != nil {
		t.Fatal(err)
	}

	probe := &contentProbeProvider{
		id: "file-scan",
		cap: api.Capability{
			ID: "malware", Version: "v1",
			InputProfiles: []api.InputProfile{{
				ID: "content",
				Requires: []api.Requirement{
					{Kind: api.ReqContent},
					{Kind: api.ReqDigest, Algorithms: []string{"sha256"}},
				},
			}},
		},
	}
	o := NewOrchestrator(st, allowPolicy{}, NewEventEmitter("test", st))
	o.providers = []api.Provider{probe}

	hex := strings.Repeat("ab", 32)
	sub := &api.Submission{
		ID:     "sub_blob",
		Status: api.SubmissionAccepted,
		Artifact: api.Artifact{
			Digests:    map[string]string{"sha256": hex},
			ContentRef: &api.ResourceReference{URI: api.BlobURN(digest)},
		},
		RequestedCapabilities: []string{"malware"},
		ResultIDs:             []string{},
	}
	if err := st.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}
	if err := o.Process(t.Context(), sub.ID); err != nil {
		t.Fatal(err)
	}
	if string(probe.got) != string(body) {
		t.Fatalf("Assess saw Content=%q want %q", probe.got, body)
	}
}

func TestProcessFailsWhenLocalBlobMissing(t *testing.T) {
	st := NewMemoryStore()
	o := NewOrchestrator(st, allowPolicy{}, NewEventEmitter("test", st))
	hex := strings.Repeat("cd", 32)
	sub := &api.Submission{
		ID:     "sub_miss",
		Status: api.SubmissionAccepted,
		Artifact: api.Artifact{
			Digests:    map[string]string{"sha256": hex},
			ContentRef: &api.ResourceReference{URI: api.BlobURN("sha256:" + hex)},
		},
		RequestedCapabilities: []string{"malware"},
		ResultIDs:             []string{},
	}
	if err := st.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}
	err := o.Process(t.Context(), sub.ID)
	if err == nil {
		t.Fatal("expected miss error")
	}
	got, ok, _ := st.GetSubmission(sub.ID)
	if !ok || got.Status != api.SubmissionFailed {
		t.Fatalf("status=%v", got)
	}
}
