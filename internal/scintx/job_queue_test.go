package scintx_test

import (
	"testing"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestMemoryJobQueue_ClaimHeartbeatComplete(t *testing.T) {
	s := scintx.NewMemoryStore()
	if err := s.EnqueueJob("sub_1"); err != nil {
		t.Fatal(err)
	}
	n, err := s.PendingJobCount()
	if err != nil || n != 1 {
		t.Fatalf("pending=%d err=%v", n, err)
	}

	id, attempts, ok, err := s.ClaimJob("owner-a", time.Minute)
	if err != nil || !ok || id != "sub_1" || attempts != 1 {
		t.Fatalf("claim: id=%s attempts=%d ok=%v err=%v", id, attempts, ok, err)
	}

	// Second claim while leased → empty.
	_, _, ok, err = s.ClaimJob("owner-b", time.Minute)
	if err != nil || ok {
		t.Fatalf("want empty while leased, ok=%v err=%v", ok, err)
	}

	hb, err := s.HeartbeatJob("sub_1", "owner-a", time.Minute)
	if err != nil || !hb {
		t.Fatalf("heartbeat: ok=%v err=%v", hb, err)
	}
	hb, err = s.HeartbeatJob("sub_1", "owner-b", time.Minute)
	if err != nil || hb {
		t.Fatalf("other owner must not heartbeat: ok=%v err=%v", hb, err)
	}

	if err := s.CompleteJob("sub_1", "owner-a"); err != nil {
		t.Fatal(err)
	}
	n, _ = s.PendingJobCount()
	if n != 0 {
		t.Fatalf("want 0 pending after complete, got %d", n)
	}
}

func TestMemoryJobQueue_ReclaimExpired(t *testing.T) {
	s := scintx.NewMemoryStore()
	_ = s.EnqueueJob("sub_x")
	id, _, ok, err := s.ClaimJob("dead", 40*time.Millisecond)
	if err != nil || !ok || id != "sub_x" {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	id2, attempts, ok, err := s.ClaimJob("alive", time.Minute)
	if err != nil || !ok || id2 != "sub_x" {
		t.Fatalf("reclaim failed: id=%s ok=%v err=%v", id2, ok, err)
	}
	if attempts < 2 {
		t.Fatalf("want attempts>=2 after reclaim, got %d", attempts)
	}
}

func TestMemoryJobQueue_EnqueueIdempotent(t *testing.T) {
	s := scintx.NewMemoryStore()
	_ = s.EnqueueJob("sub_1")
	_ = s.EnqueueJob("sub_1")
	n, _ := s.PendingJobCount()
	if n != 1 {
		t.Fatalf("want 1 job, got %d", n)
	}
}
