package workers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrBackpressure is returned when the pool is at MaxInflight (running + queued).
// HTTP maps this to 429 Too Many Requests.
var ErrBackpressure = errors.New("job queue at capacity")

// ErrPoolClosed is returned when Submit is called after Close.
var ErrPoolClosed = errors.New("worker pool closed")

// ProcessFunc runs one submission to completion (Orchestrator.Process).
type ProcessFunc func(ctx context.Context, subID string) error

// Dispatcher schedules submission processing with backpressure.
//
// Local mode (default): in-process worker pool. Scale vertically via
// SCINTX_WORKERS / SCINTX_MAX_INFLIGHT. Scale horizontally by running more
// gateway processes that share Store/Cache (postgres + redis); each process
// has its own local pool and only processes jobs it admits over HTTP.
//
// ModeQueue is reserved for a future external queue + worker fleet split.
type Dispatcher interface {
	// Submit admits subID for processing. Returns ErrBackpressure if at capacity,
	// or ErrPoolClosed if shutting down.
	Submit(ctx context.Context, subID string) error
	// Reserve acquires an admit slot without enqueueing. Use for create-submission
	// so capacity is checked before the store write (avoids abandon races).
	Reserve(ctx context.Context) (AdmitToken, error)
	// Wait blocks until workers finish (call after Close for a clean drain).
	Wait()
	// Close stops admitting jobs. Queued jobs are drained (unless workCtx is
	// cancelled). Close is idempotent and safe concurrent with Submit.
	Close() error
}

// AdmitToken holds a reserved MaxInflight slot until Commit or Release.
type AdmitToken interface {
	// Commit enqueues subID using the reserved slot. Call at most once.
	Commit(subID string) error
	// Release frees the slot without running work. Safe if Commit already ran.
	Release()
}

// Mode selects how jobs are scheduled.
const (
	ModeLocal = "local" // in-process pool (single binary — default)
	ModeQueue = "queue" // shared job table + lease claims (multi-process)
)

// Config controls the local pool and queue claim workers.
//
// MaxInflight is the hard admit limit: running + queued jobs (local mode).
// Workers is how many Process calls run concurrently (≤ MaxInflight).
// Zero MaxInflight means unlimited (no backpressure — demos only).
type Config struct {
	Mode string // local | queue

	// MaxInflight is max jobs admitted (running + waiting). 0 = unlimited.
	MaxInflight int

	// Workers is concurrent Process slots. Clamped to MaxInflight when set.
	Workers int

	// Queue-mode settings (ignored in local mode).
	Lease        time.Duration // lease TTL; expired → reclaim
	PollInterval time.Duration // idle poll when queue empty
	MaxPending   int           // enqueue backpressure threshold
	MaxAttempts  int           // after this many claims, fail the job
	WorkerID     string        // stable owner prefix (default: host-pid-rand)
}

// ConfigFromEnv reads worker env vars.
//
//	SCINTX_WORKER_MODE     local (default) | queue
//	SCINTX_MAX_INFLIGHT    total admitted jobs (running+queued); 0 = unlimited
//	SCINTX_WORKERS         concurrent Process slots (default: CPU-based, ≤ max)
//	SCINTX_JOB_QUEUE_SIZE  if set with workers: max_inflight = workers + queue
//	SCINTX_JOB_LEASE       queue lease TTL (default 2m)
//	SCINTX_JOB_POLL        queue idle poll interval (default 200ms)
//	SCINTX_MAX_PENDING_JOBS enqueue backpressure (queue mode)
//	SCINTX_JOB_MAX_ATTEMPTS max claim attempts before fail (default 8)
//	SCINTX_WORKER_ID       optional owner id prefix
func ConfigFromEnv() (Config, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SCINTX_WORKER_MODE")))
	if mode == "" {
		mode = ModeLocal
	}
	cfg := Config{Mode: mode}

	maxRaw := os.Getenv("SCINTX_MAX_INFLIGHT")
	workersRaw := os.Getenv("SCINTX_WORKERS")
	queueRaw := os.Getenv("SCINTX_JOB_QUEUE_SIZE")

	var (
		maxSet, workersSet, queueSet bool
		maxN, workersN, queueN       int
		err                          error
	)

	if maxRaw != "" {
		maxSet = true
		maxN, err = strconv.Atoi(maxRaw)
		if err != nil || maxN < 0 {
			return Config{}, fmt.Errorf("SCINTX_MAX_INFLIGHT: want integer >= 0, got %q", maxRaw)
		}
	}
	if workersRaw != "" {
		workersSet = true
		workersN, err = strconv.Atoi(workersRaw)
		if err != nil || workersN < 0 {
			return Config{}, fmt.Errorf("SCINTX_WORKERS: want integer >= 0, got %q", workersRaw)
		}
	}
	if queueRaw != "" {
		queueSet = true
		queueN, err = strconv.Atoi(queueRaw)
		if err != nil || queueN < 0 {
			return Config{}, fmt.Errorf("SCINTX_JOB_QUEUE_SIZE: want integer >= 0, got %q", queueRaw)
		}
	}

	// Explicit unlimited: MAX_INFLIGHT=0 (or WORKERS=0 with no max/queue).
	if maxSet && maxN == 0 {
		cfg.MaxInflight = 0
		cfg.Workers = 0
	} else if workersSet && workersN == 0 && !maxSet && !queueSet {
		cfg.MaxInflight = 0
		cfg.Workers = 0
	} else {
		workers := defaultWorkers()
		if workersSet && workersN > 0 {
			workers = workersN
		}

		switch {
		case queueSet:
			cfg.Workers = workers
			cfg.MaxInflight = workers + queueN
		case maxSet:
			cfg.MaxInflight = maxN
			cfg.Workers = workers
			if cfg.Workers > cfg.MaxInflight {
				cfg.Workers = cfg.MaxInflight
			}
		default:
			cfg.Workers = workers
			cfg.MaxInflight = workers + max(workers*2, 64)
		}

		if cfg.Workers < 1 && cfg.MaxInflight > 0 {
			cfg.Workers = 1
		}
	}

	if raw := os.Getenv("SCINTX_JOB_LEASE"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("SCINTX_JOB_LEASE: want positive duration, got %q", raw)
		}
		cfg.Lease = d
	}
	if raw := os.Getenv("SCINTX_JOB_POLL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("SCINTX_JOB_POLL: want positive duration, got %q", raw)
		}
		cfg.PollInterval = d
	}
	if raw := os.Getenv("SCINTX_MAX_PENDING_JOBS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("SCINTX_MAX_PENDING_JOBS: want integer >= 1, got %q", raw)
		}
		cfg.MaxPending = n
	}
	if raw := os.Getenv("SCINTX_JOB_MAX_ATTEMPTS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("SCINTX_JOB_MAX_ATTEMPTS: want integer >= 1, got %q", raw)
		}
		cfg.MaxAttempts = n
	}
	cfg.WorkerID = strings.TrimSpace(os.Getenv("SCINTX_WORKER_ID"))
	return cfg, nil
}

func defaultWorkers() int {
	n := runtime.NumCPU() * 2
	if n < 4 {
		n = 4
	}
	if n > 8 {
		n = 8
	}
	return n
}

// Open builds a Dispatcher for cfg.
// workCtx is cancelled on shutdown so in-flight Process calls abort after Close.
// For ModeQueue, pass the Store as jobs (required). Local mode ignores jobs.
func Open(cfg Config, workCtx context.Context, process ProcessFunc, jobs ...JobQueue) (Dispatcher, error) {
	if process == nil {
		return nil, errors.New("workers: process func is required")
	}
	if workCtx == nil {
		workCtx = context.Background()
	}
	var jq JobQueue
	if len(jobs) > 0 {
		jq = jobs[0]
	}
	switch strings.ToLower(cfg.Mode) {
	case ModeLocal, "":
		return newLocalPool(cfg, workCtx, process)
	case ModeQueue:
		return newQueuePool(cfg, workCtx, process, jq)
	default:
		return nil, fmt.Errorf("unknown SCINTX_WORKER_MODE %q (want local|queue)", cfg.Mode)
	}
}

type localPool struct {
	mu      sync.Mutex
	closed  bool
	jobs    chan string
	sem     chan struct{} // admit tokens; len == MaxInflight
	process ProcessFunc
	workCtx context.Context
	wg      sync.WaitGroup

	unlimited bool
	unlimWG   sync.WaitGroup
}

func newLocalPool(cfg Config, workCtx context.Context, process ProcessFunc) (*localPool, error) {
	p := &localPool{
		process: process,
		workCtx: workCtx,
	}

	if cfg.MaxInflight == 0 {
		p.unlimited = true
		slog.Info("worker pool: unlimited (SCINTX_MAX_INFLIGHT=0); backpressure disabled")
		return p, nil
	}

	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > cfg.MaxInflight {
		workers = cfg.MaxInflight
	}

	// sem caps total outstanding (queued + running). jobs buffer can hold every
	// admitted id so workers may start slowly without false backpressure.
	p.sem = make(chan struct{}, cfg.MaxInflight)
	p.jobs = make(chan string, cfg.MaxInflight)

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.loop()
	}
	slog.Info("worker pool started",
		"mode", ModeLocal,
		"workers", workers,
		"max_inflight", cfg.MaxInflight,
	)
	return p, nil
}

func (p *localPool) loop() {
	defer p.wg.Done()
	for subID := range p.jobs {
		func(subID string) {
			defer func() { <-p.sem }() // release admit token when Process returns
			defer func() {
				if r := recover(); r != nil {
					slog.Error("process panic", "submission_id", subID, "panic", r)
				}
			}()
			if err := p.process(p.workCtx, subID); err != nil {
				slog.Error("process failed", "submission_id", subID, "err", err)
			}
		}(subID)
	}
}

type admitToken struct {
	pool      *localPool
	released  bool
	committed bool
}

func (p *localPool) Reserve(ctx context.Context) (AdmitToken, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrPoolClosed
	}
	if p.unlimited {
		return &admitToken{pool: p}, nil
	}
	select {
	case p.sem <- struct{}{}:
		return &admitToken{pool: p}, nil
	default:
		return nil, ErrBackpressure
	}
}

func (t *admitToken) Commit(subID string) error {
	p := t.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if t.released || t.committed {
		return fmt.Errorf("admit token already used")
	}
	if p.closed {
		t.releaseLocked()
		return ErrPoolClosed
	}
	if p.unlimited {
		t.committed = true
		p.unlimWG.Add(1)
		go func() {
			defer p.unlimWG.Done()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("process panic", "submission_id", subID, "panic", r)
				}
			}()
			if err := p.process(p.workCtx, subID); err != nil {
				slog.Error("process failed", "submission_id", subID, "err", err)
			}
		}()
		return nil
	}
	select {
	case p.jobs <- subID:
		t.committed = true
		return nil
	default:
		t.releaseLocked()
		return ErrBackpressure
	}
}

func (t *admitToken) Release() {
	p := t.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	t.releaseLocked()
}

func (t *admitToken) releaseLocked() {
	if t.released || t.committed {
		return
	}
	t.released = true
	if t.pool.unlimited || t.pool.sem == nil {
		return
	}
	select {
	case <-t.pool.sem:
	default:
	}
}

func (p *localPool) Submit(ctx context.Context, subID string) error {
	tok, err := p.Reserve(ctx)
	if err != nil {
		return err
	}
	if err := tok.Commit(subID); err != nil {
		tok.Release()
		return err
	}
	return nil
}

func (p *localPool) Wait() {
	if p.unlimited {
		p.unlimWG.Wait()
		return
	}
	p.wg.Wait()
}

func (p *localPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.jobs != nil {
		close(p.jobs) // workers drain remaining jobs then exit
	}
	return nil
}
