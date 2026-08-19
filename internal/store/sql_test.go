package store_test

import (
	"errors"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/store"
)

func TestSQLiteStore_RoundTrip(t *testing.T) {
	st, err := store.Open(store.Config{Driver: store.DriverSQLite, SQLitePath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sub := &api.Submission{ID: "sub_1", Status: api.SubmissionAccepted, ResultIDs: []string{}}
	stored, created, err := st.PutSubmissionIdempotent("idem-1", "hash-1", sub)
	if err != nil || !created || stored.ID != "sub_1" {
		t.Fatalf("create: created=%v err=%v stored=%v", created, err, stored)
	}
	again, created, err := st.PutSubmissionIdempotent("idem-1", "hash-1", &api.Submission{ID: "sub_other"})
	if err != nil || created || again.ID != "sub_1" {
		t.Fatalf("replay: created=%v id=%s err=%v", created, again.ID, err)
	}
	_, _, err = st.PutSubmissionIdempotent("idem-1", "hash-other", &api.Submission{ID: "sub_x"})
	if !errors.Is(err, scintx.ErrIdempotencyConflict) {
		t.Fatalf("want conflict, got %v", err)
	}

	if err := st.AbandonSubmission("sub_1", "idem-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.GetSubmission("sub_1"); err != nil || ok {
		t.Fatalf("abandoned submission should be gone ok=%v err=%v", ok, err)
	}
	recreated, created, err := st.PutSubmissionIdempotent("idem-1", "hash-1", &api.Submission{ID: "sub_2", Status: api.SubmissionAccepted, ResultIDs: []string{}})
	if err != nil || !created || recreated.ID != "sub_2" {
		t.Fatalf("idempotency should be free after abandon: created=%v id=%v err=%v", created, recreated, err)
	}

	res := &api.ProviderResult{ID: "res_1", SubmissionID: "sub_2", SchemaVersion: "1.0.0"}
	if err := st.PutResult(res); err != nil {
		t.Fatal(err)
	}
	list, err := st.GetResultsForSubmission("sub_2")
	if err != nil || len(list) != 1 {
		t.Fatalf("results: len=%d err=%v", len(list), err)
	}

	if err := st.PutArtifact("sha256:abc", []byte("hi")); err != nil {
		t.Fatal(err)
	}
	ok, err := st.HasArtifact("sha256:abc")
	if err != nil || !ok {
		t.Fatalf("artifact missing")
	}

	if err := st.RegisterProvider(scintx.ProviderEntry{
		ID: "p1", Name: "p1",
		Capabilities: api.ProviderCapabilities{SchemaVersion: "1.0.0"},
	}); err != nil {
		t.Fatal(err)
	}
	providers, err := st.Providers()
	if err != nil || len(providers) != 1 {
		t.Fatalf("providers: %#v err=%v", providers, err)
	}
}

func TestSQLiteStore_ClaimResume(t *testing.T) {
	st, err := store.Open(store.Config{Driver: store.DriverSQLite, SQLitePath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sub := &api.Submission{ID: "sub_d", Status: api.SubmissionDeferred, ResultIDs: []string{}}
	if err := st.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}
	got, err := st.ClaimResume("sub_d")
	if err != nil || got.Status != api.SubmissionRunning {
		t.Fatalf("claim: err=%v status=%v", err, got)
	}
	if _, err := st.ClaimResume("sub_d"); !errors.Is(err, scintx.ErrResumeNotDeferred) {
		t.Fatalf("second claim: %v", err)
	}
}

func TestOpen_UnknownDriver(t *testing.T) {
	_, err := store.Open(store.Config{Driver: "redis"})
	if err == nil {
		t.Fatal("expected error")
	}
}
