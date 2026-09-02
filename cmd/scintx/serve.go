package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yeeth-security/scintx/api"
	_ "github.com/yeeth-security/scintx/extensions/policies/all"
	_ "github.com/yeeth-security/scintx/extensions/providers/all"
	"github.com/yeeth-security/scintx/internal/auth"
	"github.com/yeeth-security/scintx/internal/cache"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
	"github.com/yeeth-security/scintx/internal/store"
	"github.com/yeeth-security/scintx/internal/webhook"
	"github.com/yeeth-security/scintx/internal/workers"
)

// runServe starts the HTTP gateway (default when no subcommand is given).
func runServe() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	storeCfg := store.ConfigFromEnv()
	st, err := store.Open(storeCfg)
	if err != nil {
		slog.Error("failed to open store", "driver", storeCfg.Driver, "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()
	// Unset / memory = ephemeral forwarder: process submissions in-process;
	// state is lost on restart. sqlite/postgres are durable stores.
	if storeCfg.Driver == store.DriverMemory || storeCfg.Driver == "" {
		slog.Info("store opened", "driver", "memory", "mode", "forwarder",
			"note", "ephemeral; set SCINTX_STORE=sqlite|postgres for durable state")
	} else {
		slog.Info("store opened", "driver", storeCfg.Driver, "mode", "durable")
	}

	emitter := scintx.NewEventEmitter("https://scintx.example", st)

	webhookCfg, err := webhook.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid webhook config", "err", err)
		os.Exit(1)
	}
	deliverer, err := webhook.Open(webhookCfg)
	if err != nil {
		slog.Error("failed to open webhook deliverer", "err", err)
		os.Exit(1)
	}
	if deliverer != nil {
		emitter.Deliverer = deliverer
		slog.Info("webhook delivery enabled", "url", webhookCfg.URL)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = deliverer.Close(ctx)
		}()
	} else {
		slog.Info("webhook delivery disabled (set SCINTX_WEBHOOK_URL to enable)")
	}

	// Load YAML policy engine (documents under SCINTX_POLICIES_DIR, default ./policies).
	policyName := os.Getenv("SCINTX_POLICY_ENGINE")
	if policyName == "" {
		policyName = "yaml"
	}
	policy, err := api.LoadPolicyEngine(policyName)
	if err != nil {
		slog.Error("failed to load policy engine", "engine", policyName, "err", err)
		os.Exit(1)
	}
	slog.Info("policy engine loaded", "engine", policy.ID())

	cacheCfg, err := cache.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid cache config", "err", err)
		os.Exit(1)
	}
	resultCache, err := cache.Open(cacheCfg)
	if err != nil {
		slog.Error("failed to open cache", "backend", cacheCfg.Backend, "err", err)
		os.Exit(1)
	}
	defer func() { _ = resultCache.Close() }()
	slog.Info("cache opened", "backend", cacheCfg.Backend, "ttl", cache.DefaultTTL(cacheCfg).String())

	orchOpts := []scintx.OrchestratorOption{
		scintx.WithResultCache(resultCache, cache.DefaultTTL(cacheCfg)),
		scintx.WithResultAggregator(scintx.NewDefaultAggregator()),
	}
	adjAllow := scintx.ParseAdjudicationForwardAllowlist()
	orchOpts = append(orchOpts, scintx.WithAdjudicationForwarding(adjAllow))

	// DefaultAggregator correlates findings across providers (same CVE → one MergedFinding).
	orch := scintx.NewOrchestrator(st, policy, emitter, orchOpts...)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		slog.Error("failed to load providers", "err", err)
		os.Exit(1)
	}

	slog.Info("SCINTX started", "providers", len(orch.Providers()))
	for _, p := range orch.Providers() {
		slog.Info("provider registered", "id", p.ID())
	}
	if len(adjAllow) > 0 {
		ids := make([]string, 0, len(adjAllow))
		for id := range adjAllow {
			ids = append(ids, id)
		}
		slog.Info("adjudication forwarding enabled", "providers", ids)
	} else {
		slog.Info("adjudication forwarding disabled (set SCINTX_FORWARD_ADJUDICATIONS to enable)")
	}

	// Build HTTP server first so the worker pool shares its cancellable root context.
	srv := server.New(st, orch, emitter, nil)

	authCfg, err := auth.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid auth config", "err", err)
		os.Exit(1)
	}
	if v := auth.NewVerifier(authCfg); v != nil {
		srv.SetAuth(v)
		slog.Info("inbound auth enabled", "profiles", authCfg.Profiles)
	} else {
		slog.Info("inbound auth disabled (set SCINTX_AUTH=hmac and/or bearer to enable)")
	}

	workerCfg, err := workers.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid worker config", "err", err)
		os.Exit(1)
	}
	dispatcher, err := workers.Open(workerCfg, srv.RootContext(), orch.Process, st)
	if err != nil {
		slog.Error("failed to start worker pool", "err", err)
		os.Exit(1)
	}
	srv.SetDispatcher(dispatcher)
	slog.Info("worker pool ready",
		"mode", workerCfg.Mode,
		"workers", workerCfg.Workers,
		"max_inflight", workerCfg.MaxInflight,
		"lease", workerCfg.Lease.String(),
	)

	addr := os.Getenv("SCINTX_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// Graceful shutdown on SIGINT/SIGTERM: stop HTTP, cancel jobs, drain.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("SCINTX listening", "addr", addr)
		errCh <- srv.Start(addr)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "err", err)
		}
		// Do not Close store/cache while workers may still write.
		if !srv.WorkersDrained() {
			slog.Warn("workers still draining; waiting extra before closing store")
			extra, cancelExtra := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelExtra()
			if err := srv.WaitWorkers(extra); err != nil {
				slog.Error("workers did not finish; store close may race", "err", err)
				os.Exit(1)
			}
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	}
}
