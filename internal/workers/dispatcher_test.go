package workers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalPoolBackpressure(t *testing.T) {
	// max_inflight=2: two admits succeed while blocked; third fails.
	block := make(chan struct{})
	var started atomic.Int32

	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 2}, context.Background(),
		func(ctx context.Context, subID string) error {
			started.Add(1)
			<-block
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(block)
		_ = d.Close()
		d.Wait()
	}()

	if err := d.Submit(context.Background(), "a"); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if err := d.Submit(context.Background(), "b"); err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if err := d.Submit(context.Background(), "c"); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for started.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if started.Load() < 1 {
		t.Fatal("worker never started")
	}
}

func TestLocalPoolExactMaxInflight(t *testing.T) {
	block := make(chan struct{})
	var started atomic.Int32

	d, err := Open(Config{Mode: ModeLocal, Workers: 2, MaxInflight: 2}, context.Background(),
		func(ctx context.Context, subID string) error {
			started.Add(1)
			<-block
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(block)
		_ = d.Close()
		d.Wait()
	}()

	if err := d.Submit(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(context.Background(), "b"); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(context.Background(), "c"); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for started.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if started.Load() != 2 {
		t.Fatalf("want 2 started, got %d", started.Load())
	}
}

func TestTokenReleasedAfterProcess(t *testing.T) {
	// After a job finishes, its admit token must free capacity for the next.
	release := make(chan struct{})
	var phase atomic.Int32

	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 1}, context.Background(),
		func(ctx context.Context, subID string) error {
			if phase.Load() == 0 {
				<-release
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	if err := d.Submit(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := d.Submit(context.Background(), "b"); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want ErrBackpressure while a runs, got %v", err)
	}
	phase.Store(1)
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := d.Submit(context.Background(), "b"); err == nil {
			return
		} else if !errors.Is(err, ErrBackpressure) {
			t.Fatalf("unexpected: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("token never released")
}

func TestSubmitAfterClose(t *testing.T) {
	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 4}, context.Background(),
		func(ctx context.Context, subID string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	d.Wait()
	if err := d.Submit(context.Background(), "x"); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("want ErrPoolClosed, got %v", err)
	}
}

func TestCloseSubmitNoPanic(t *testing.T) {
	d, err := Open(Config{Mode: ModeLocal, Workers: 4, MaxInflight: 32}, context.Background(),
		func(ctx context.Context, subID string) error {
			time.Sleep(time.Millisecond)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Submit(context.Background(), "job")
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		_ = d.Close()
	}()
	wg.Wait()
	d.Wait()
}

func TestReserveThenCommit(t *testing.T) {
	var ran atomic.Int32
	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 1}, context.Background(),
		func(ctx context.Context, subID string) error {
			ran.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	tok, err := d.Reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Pool is full while token held.
	if err := d.Submit(context.Background(), "x"); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want backpressure while reserved, got %v", err)
	}
	if err := tok.Commit("a"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for ran.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ran.Load() != 1 {
		t.Fatal("commit did not run process")
	}
}

func TestReserveReleaseFreesSlot(t *testing.T) {
	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 1}, context.Background(),
		func(ctx context.Context, subID string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	tok, err := d.Reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok.Release()
	if err := d.Submit(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
}

func TestUnlimitedRunsJobs(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	d, err := Open(Config{Mode: ModeLocal, MaxInflight: 0}, context.Background(),
		func(ctx context.Context, subID string) error {
			wg.Done()
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	_ = d.Submit(context.Background(), "x")
	_ = d.Submit(context.Background(), "y")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("unlimited jobs did not finish")
	}
}

func TestQueueModeRejectedWithoutStore(t *testing.T) {
	_, err := Open(Config{Mode: ModeQueue, Workers: 1, MaxInflight: 1}, context.Background(),
		func(ctx context.Context, subID string) error { return nil })
	if err == nil {
		t.Fatal("expected queue mode error without JobQueue")
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("SCINTX_WORKER_MODE", "")
	t.Setenv("SCINTX_MAX_INFLIGHT", "")
	t.Setenv("SCINTX_WORKERS", "")
	t.Setenv("SCINTX_JOB_QUEUE_SIZE", "")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeLocal {
		t.Fatalf("mode: %q", cfg.Mode)
	}
	if cfg.Workers < 1 || cfg.MaxInflight < cfg.Workers {
		t.Fatalf("workers=%d max=%d", cfg.Workers, cfg.MaxInflight)
	}
}

func TestConfigFromEnvMaxInflight(t *testing.T) {
	t.Setenv("SCINTX_MAX_INFLIGHT", "10")
	t.Setenv("SCINTX_WORKERS", "4")
	t.Setenv("SCINTX_JOB_QUEUE_SIZE", "")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxInflight != 10 || cfg.Workers != 4 {
		t.Fatalf("got %+v", cfg)
	}
}

func TestConfigFromEnvQueueSize(t *testing.T) {
	t.Setenv("SCINTX_MAX_INFLIGHT", "")
	t.Setenv("SCINTX_WORKERS", "3")
	t.Setenv("SCINTX_JOB_QUEUE_SIZE", "7")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workers != 3 || cfg.MaxInflight != 10 {
		t.Fatalf("got %+v", cfg)
	}
}

func TestConfigFromEnvUnlimited(t *testing.T) {
	t.Setenv("SCINTX_MAX_INFLIGHT", "0")
	t.Setenv("SCINTX_WORKERS", "")
	t.Setenv("SCINTX_JOB_QUEUE_SIZE", "")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxInflight != 0 {
		t.Fatalf("want unlimited, got %+v", cfg)
	}
}
