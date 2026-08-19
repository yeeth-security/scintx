package store_test

import (
	"testing"
	"time"

	"github.com/yeeth-security/scintx/internal/store"
)

func TestSQLiteJobQueue_ClaimReclaimComplete(t *testing.T) {
	st, err := store.Open(store.Config{Driver: store.DriverSQLite, SQLitePath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.EnqueueJob("sub_sql"); err != nil {
		t.Fatal(err)
	}
	n, err := st.PendingJobCount()
	if err != nil || n != 1 {
		t.Fatalf("pending=%d err=%v", n, err)
	}

	id, attempts, ok, err := st.ClaimJob("w1", time.Minute)
	if err != nil || !ok || id != "sub_sql" || attempts != 1 {
		t.Fatalf("claim: id=%s attempts=%d ok=%v err=%v", id, attempts, ok, err)
	}

	_, _, ok, err = st.ClaimJob("w2", time.Minute)
	if err != nil || ok {
		t.Fatalf("want empty while leased, ok=%v err=%v", ok, err)
	}

	okHB, err := st.HeartbeatJob("sub_sql", "w1", time.Minute)
	if err != nil || !okHB {
		t.Fatalf("heartbeat: %v %v", okHB, err)
	}

	if err := st.CompleteJob("sub_sql", "w1"); err != nil {
		t.Fatal(err)
	}
	n, _ = st.PendingJobCount()
	if n != 0 {
		t.Fatalf("want 0 after complete, got %d", n)
	}
}

func TestSQLiteJobQueue_ReclaimExpiredLease(t *testing.T) {
	st, err := store.Open(store.Config{Driver: store.DriverSQLite, SQLitePath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.EnqueueJob("sub_exp")
	_, _, ok, err := st.ClaimJob("dead", 40*time.Millisecond)
	if err != nil || !ok {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	id, attempts, ok, err := st.ClaimJob("alive", time.Minute)
	if err != nil || !ok || id != "sub_exp" {
		t.Fatalf("reclaim: id=%s ok=%v err=%v", id, ok, err)
	}
	if attempts < 2 {
		t.Fatalf("attempts=%d", attempts)
	}
}
