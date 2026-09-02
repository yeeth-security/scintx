package workers

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

// JobQueue is the cross-process work queue (implemented by Store backends).
type JobQueue interface {
	EnqueueJob(submissionID string) error
	DeleteJob(submissionID string) error
	ClaimJob(owner string, lease time.Duration) (submissionID string, attempts int, ok bool, err error)
	HeartbeatJob(submissionID, owner string, lease time.Duration) (ok bool, err error)
	CompleteJob(submissionID, owner string) error
	PendingJobCount() (int, error)
	GetSubmission(id string) (*api.Submission, bool, error)
	PutSubmission(sub *api.Submission) error
}

// queuePool claims jobs from a shared store so work auto-balances across
// processes. Expired leases are reclaimed when a worker dies.
type queuePool struct {
	mu       sync.Mutex
	closed   bool
	cfg      Config
	jobs     JobQueue
	process  ProcessFunc
	workCtx  context.Context
	owner    string
	wg       sync.WaitGroup
	inflight sync.WaitGroup
}

func newQueuePool(cfg Config, workCtx context.Context, process ProcessFunc, jobs JobQueue) (*queuePool, error) {
	if jobs == nil {
		return nil, fmt.Errorf("workers: queue mode requires a JobQueue store (sqlite/postgres/memory)")
	}
	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if cfg.MaxInflight > 0 && workers > cfg.MaxInflight {
		workers = cfg.MaxInflight
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 2 * time.Minute
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 200 * time.Millisecond
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 8
	}
	if cfg.MaxPending < 1 {
		cfg.MaxPending = max(cfg.MaxInflight*10, 256)
		if cfg.MaxInflight == 0 {
			cfg.MaxPending = 1024
		}
	}
	owner := cfg.WorkerID
	if owner == "" {
		owner = defaultWorkerID()
	}

	p := &queuePool{
		cfg:     cfg,
		jobs:    jobs,
		process: process,
		workCtx: workCtx,
		owner:   owner,
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.claimLoop(i)
	}
	slog.Info("worker pool started",
		"mode", ModeQueue,
		"workers", workers,
		"max_pending", cfg.MaxPending,
		"lease", cfg.Lease.String(),
		"owner", owner,
	)
	return p, nil
}

func defaultWorkerID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "host"
	}
	return fmt.Sprintf("%s-%d-%s", host, os.Getpid(), api.RandHex()[:8])
}

func (p *queuePool) claimLoop(workerN int) {
	defer p.wg.Done()
	owner := fmt.Sprintf("%s-w%d", p.owner, workerN)
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if p.isClosed() {
			return
		}
		select {
		case <-p.workCtx.Done():
			return
		default:
		}

		id, attempts, ok, err := p.jobs.ClaimJob(owner, p.cfg.Lease)
		if err != nil {
			slog.Error("claim job", "err", err)
			select {
			case <-p.workCtx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		if !ok {
			select {
			case <-p.workCtx.Done():
				return
			case <-ticker.C:
			}
			continue
		}

		p.inflight.Add(1)
		p.runClaimed(owner, id, attempts)
		p.inflight.Done()
	}
}

func (p *queuePool) runClaimed(owner, subID string, attempts int) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("process panic; lease will expire for reclaim", "submission_id", subID, "panic", r)
		}
	}()

	sub, ok, err := p.jobs.GetSubmission(subID)
	if err != nil || !ok {
		_ = p.jobs.CompleteJob(subID, owner)
		return
	}
	if sub.Status == api.SubmissionCompleted || sub.Status == api.SubmissionFailed {
		_ = p.jobs.CompleteJob(subID, owner)
		return
	}
	if attempts > p.cfg.MaxAttempts {
		reason := api.CompletionFailed
		now := time.Now().UTC()
		sub.Status = api.SubmissionFailed
		sub.CompletionReason = &reason
		sub.CompletedAt = &now
		_ = p.jobs.PutSubmission(sub)
		_ = p.jobs.CompleteJob(subID, owner)
		slog.Error("job exceeded max attempts", "submission_id", subID, "attempts", attempts)
		return
	}

	ctx, cancel := context.WithCancel(p.workCtx)
	defer cancel()

	var hbDone atomic.Bool
	go func() {
		t := time.NewTicker(p.cfg.Lease / 3)
		defer t.Stop()
		for {
			if hbDone.Load() {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ok, err := p.jobs.HeartbeatJob(subID, owner, p.cfg.Lease)
				if err != nil || !ok {
					slog.Warn("lost job lease", "submission_id", subID, "err", err)
					cancel()
					return
				}
			}
		}
	}()

	err = p.process(ctx, subID)
	hbDone.Store(true)
	if err != nil {
		slog.Error("process failed", "submission_id", subID, "err", err)
	}
	if cerr := p.jobs.CompleteJob(subID, owner); cerr != nil {
		slog.Error("complete job", "submission_id", subID, "err", cerr)
	}
}

func (p *queuePool) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

type queueToken struct {
	pool      *queuePool
	released  bool
	committed bool
}

func (p *queuePool) Reserve(ctx context.Context) (AdmitToken, error) {
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
	n, err := p.jobs.PendingJobCount()
	if err != nil {
		return nil, err
	}
	if n >= p.cfg.MaxPending {
		return nil, ErrBackpressure
	}
	return &queueToken{pool: p}, nil
}

func (t *queueToken) Commit(subID string) error {
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	if t.released || t.committed {
		return fmt.Errorf("admit token already used")
	}
	if t.pool.closed {
		t.released = true
		return ErrPoolClosed
	}
	if err := t.pool.jobs.EnqueueJob(subID); err != nil {
		return err
	}
	t.committed = true
	return nil
}

func (t *queueToken) Release() {
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	if t.released || t.committed {
		return
	}
	t.released = true
}

func (p *queuePool) Submit(ctx context.Context, subID string) error {
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

func (p *queuePool) Wait() {
	p.wg.Wait()
	p.inflight.Wait()
}

func (p *queuePool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

var _ JobQueue = (scintx.Store)(nil)
