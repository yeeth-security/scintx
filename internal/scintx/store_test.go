package scintx_test

import (
	"errors"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestMemoryStore_CopyOnReadIsolation(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_1", Status: api.SubmissionAccepted}
	if err := s.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.GetSubmission("sub_1")
	if err != nil || !ok {
		t.Fatalf("missing submission ok=%v err=%v", ok, err)
	}
	got.Status = api.SubmissionRunning

	again, _, err := s.GetSubmission("sub_1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != api.SubmissionAccepted {
		t.Fatalf("mutation leaked into store: %s", again.Status)
	}
}

func TestMemoryStore_IdempotencyKey(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_a", Status: api.SubmissionAccepted}
	if err := s.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}
	if err := s.RememberIdempotencyKey("k1", "sub_a"); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.GetSubmissionByIdempotencyKey("k1")
	if err != nil || !ok || got.ID != "sub_a" {
		t.Fatalf("lookup failed: ok=%v got=%v err=%v", ok, got, err)
	}

	if err := s.RememberIdempotencyKey("k1", "sub_other"); err != nil {
		t.Fatal(err)
	}
	got, _, err = s.GetSubmissionByIdempotencyKey("k1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "sub_a" {
		t.Fatalf("idempotency overwritten: %s", got.ID)
	}
}

func TestMemoryStore_AbandonSubmission(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_a", Status: api.SubmissionAccepted, ResultIDs: []string{}}
	if _, _, err := s.PutSubmissionIdempotent("k1", "hash-a", sub); err != nil {
		t.Fatal(err)
	}
	if err := s.AbandonSubmission("sub_a", "k1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSubmission("sub_a"); ok {
		t.Fatal("submission should be gone")
	}
	sub2 := &api.Submission{ID: "sub_b", Status: api.SubmissionAccepted, ResultIDs: []string{}}
	stored, created, err := s.PutSubmissionIdempotent("k1", "hash-a", sub2)
	if err != nil || !created || stored.ID != "sub_b" {
		t.Fatalf("recreate: created=%v id=%v err=%v", created, stored, err)
	}
}

func TestMemoryStore_AbandonRejectsNonAccepted(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_a", Status: api.SubmissionRunning, ResultIDs: []string{}}
	_ = s.PutSubmission(sub)
	if err := s.AbandonSubmission("sub_a", ""); !errors.Is(err, scintx.ErrAbandonRejected) {
		t.Fatalf("want ErrAbandonRejected, got %v", err)
	}
}

func TestMemoryStore_IdempotencyConflict(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_a", Status: api.SubmissionAccepted, ResultIDs: []string{}}
	if _, _, err := s.PutSubmissionIdempotent("k1", "hash-a", sub); err != nil {
		t.Fatal(err)
	}
	other := &api.Submission{ID: "sub_b", Status: api.SubmissionAccepted, ResultIDs: []string{}}
	_, _, err := s.PutSubmissionIdempotent("k1", "hash-b", other)
	if !errors.Is(err, scintx.ErrIdempotencyConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}

func TestMemoryStore_ClaimResumeAtomic(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{ID: "sub_a", Status: api.SubmissionDeferred, ResultIDs: []string{}}
	_ = s.PutSubmission(sub)

	got, err := s.ClaimResume("sub_a")
	if err != nil || got.Status != api.SubmissionRunning {
		t.Fatalf("claim: %v status=%v", err, got)
	}
	if _, err := s.ClaimResume("sub_a"); !errors.Is(err, scintx.ErrResumeNotDeferred) {
		t.Fatalf("second claim want ErrResumeNotDeferred, got %v", err)
	}
	if err := s.ReleaseResume("sub_a"); err != nil {
		t.Fatal(err)
	}
	again, ok, _ := s.GetSubmission("sub_a")
	if !ok || again.Status != api.SubmissionDeferred {
		t.Fatalf("release: %+v", again)
	}
}

func TestRequestFingerprintStable(t *testing.T) {
	purl := "pkg:pypi/x@1"
	a := api.Artifact{PURL: &purl}
	h1 := scintx.RequestFingerprint("1.0.0", a, []string{"b", "a"}, nil)
	h2 := scintx.RequestFingerprint("1.0.0", a, []string{"a", "b"}, nil)
	if h1 != h2 {
		t.Fatal("capability order must not change fingerprint")
	}
	h3 := scintx.RequestFingerprint("1.0.0", a, []string{"a"}, nil)
	if h1 == h3 {
		t.Fatal("different caps must change fingerprint")
	}
}
