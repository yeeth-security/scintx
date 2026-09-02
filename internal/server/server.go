package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/auth"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/workers"
)

const (
	// maxJSONBody caps JSON request bodies (submissions, etc.).
	maxJSONBody = 1 << 20 // 1 MiB
	// defaultMaxArtifactBody caps binary artifact uploads (large VSIX).
	// Override with SCINTX_MAX_ARTIFACT_BYTES (integer byte count).
	defaultMaxArtifactBody int64 = 1 << 30 // 1 GiB
)

// maxArtifactBodyBytes returns the upload size cap. Default 1 GiB so large
// VSIX / binary artifacts fit; operators can lower it via env.
func maxArtifactBodyBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("SCINTX_MAX_ARTIFACT_BYTES"))
	if raw == "" {
		return defaultMaxArtifactBody
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		slog.Default().Warn("invalid SCINTX_MAX_ARTIFACT_BYTES; using default",
			"value", raw, "default", defaultMaxArtifactBody)
		return defaultMaxArtifactBody
	}
	return n
}

// Server is the HTTP adapter over Store + Orchestrator + job Dispatcher.
type Server struct {
	store        scintx.Store
	orchestrator *scintx.Orchestrator
	dispatcher   workers.Dispatcher
	emitter      *scintx.EventEmitter
	httpServer   *http.Server
	// rootCtx is cancelled on Shutdown so in-flight Process calls stop.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	log        *slog.Logger
	auth       *auth.Verifier

	// workersDrained is true when Shutdown finished Wait successfully.
	workersDrained atomic.Bool
}

// New builds a Server. dispatcher may be nil only in tests that never enqueue.
func New(store scintx.Store, orch *scintx.Orchestrator, emitter *scintx.EventEmitter, dispatcher workers.Dispatcher) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		store:        store,
		orchestrator: orch,
		dispatcher:   dispatcher,
		emitter:      emitter,
		rootCtx:      ctx,
		rootCancel:   cancel,
		log:          slog.Default(),
	}
}

// SetDispatcher attaches the job pool (call before Start).
func (s *Server) SetDispatcher(d workers.Dispatcher) { s.dispatcher = d }

// SetAuth attaches inbound API authentication (nil disables).
func (s *Server) SetAuth(v *auth.Verifier) { s.auth = v }

// RootContext is cancelled on Shutdown; pass it to workers.Open as workCtx.
func (s *Server) RootContext() context.Context { return s.rootCtx }

// Routes returns the mux with all v1 handlers.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submissions", s.createSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}", s.getSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}/results", s.listSubmissionResults)
	mux.HandleFunc("GET /v1/submissions/{id}/merged", s.getMergedResult)
	mux.HandleFunc("POST /v1/submissions/{id}/resume", s.resumeSubmission)
	mux.HandleFunc("POST /v1/submissions/{id}/adjudicate", s.adjudicateSubmission)
	mux.HandleFunc("GET /v1/results/{id}", s.getResult)
	mux.HandleFunc("GET /v1/decisions/{id}", s.getDecision)
	mux.HandleFunc("GET /v1/providers", s.listProviders)
	mux.HandleFunc("GET /v1/providers/{id}/capabilities", s.getProviderCapabilities)
	mux.HandleFunc("POST /v1/artifacts", s.uploadArtifact)
	mux.HandleFunc("HEAD /v1/artifacts/{digest}", s.checkArtifact)
	mux.HandleFunc("GET /v1/.well-known/scintx", s.wellKnown)
	mux.HandleFunc("GET /v1/events", s.listEvents)
	if s.auth != nil {
		return s.auth.Middleware(mux)
	}
	return mux
}

// Start listens on addr with hardened http.Server timeouts.
func (s *Server) Start(addr string) error {
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// Long enough for large artifact uploads (default cap 1 GiB).
		// Headers are still bounded by ReadHeaderTimeout above.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown stops HTTP first, then stops admitting jobs, cancels in-flight
// Process calls, and waits for workers to exit (bounded by ctx).
func (s *Server) Shutdown(ctx context.Context) error {
	s.workersDrained.Store(false)
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Shutdown(ctx)
	}
	if s.dispatcher != nil {
		_ = s.dispatcher.Close()
	}
	if s.rootCancel != nil {
		s.rootCancel()
	}
	if s.dispatcher != nil {
		done := make(chan struct{})
		go func() {
			s.dispatcher.Wait()
			close(done)
		}()
		select {
		case <-done:
			s.workersDrained.Store(true)
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
		}
	} else {
		s.workersDrained.Store(true)
	}
	return err
}

// WorkersDrained reports whether Shutdown completed a full worker Wait.
// main must not Close the store/cache until this is true.
func (s *Server) WorkersDrained() bool { return s.workersDrained.Load() }

// WaitWorkers blocks until the dispatcher finishes (or ctx ends).
func (s *Server) WaitWorkers(ctx context.Context) error {
	if s.dispatcher == nil {
		s.workersDrained.Store(true)
		return nil
	}
	done := make(chan struct{})
	go func() {
		s.dispatcher.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.workersDrained.Store(true)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Default().Warn("writeJSON encode failed", "err", err)
	}
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.ProblemDetails{
		Type:   "https://scintx.example/problems/" + title,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

func writeBackpressure(w http.ResponseWriter, detail string) {
	w.Header().Set("Retry-After", "2")
	writeProblem(w, http.StatusTooManyRequests, "capacity_exceeded", detail)
}

// abandonUnprocessed drops a submission that never entered the worker pool so
// clients can retry (including with the same Idempotency-Key).
func (s *Server) abandonUnprocessed(id, idemKey string) {
	if err := s.store.AbandonSubmission(id, idemKey); err != nil {
		s.log.Error("abandon submission after dispatch failure", "submission_id", id, "err", err)
	}
}

type createSubmissionRequest struct {
	SchemaVersion         string       `json:"schema_version"`
	Artifact              api.Artifact `json:"artifact"`
	RequestedCapabilities []string     `json:"requested_capabilities,omitempty"`
	PolicyRef             *string      `json:"policy_ref,omitempty"`
	IdempotencyKey        string       `json:"-"`
}

func (s *Server) createSubmission(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	var req createSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, 400, "invalid_request", err.Error())
		return
	}
	req.IdempotencyKey = r.Header.Get("Idempotency-Key")

	if req.SchemaVersion == "" {
		req.SchemaVersion = "1.0.0"
	}
	if req.Artifact.PURL == nil && len(req.Artifact.Digests) == 0 && req.Artifact.ContentRef == nil {
		writeProblem(w, 422, "invalid_artifact", "artifact must have at least one of purl, digests, or content_ref+digests")
		return
	}
	if req.Artifact.ContentRef != nil && len(req.Artifact.Digests) == 0 {
		writeProblem(w, 422, "invalid_artifact", "content_ref without digests is not allowed in v1")
		return
	}
	if req.Artifact.PURL != nil {
		cp, err := api.CanonicalPurl(*req.Artifact.PURL)
		if err != nil {
			writeProblem(w, 422, "invalid_purl", err.Error())
			return
		}
		req.Artifact.PURL = &cp
	}

	sub := &api.Submission{
		ID:                    "sub_" + api.RandHex(),
		SchemaVersion:         req.SchemaVersion,
		Artifact:              req.Artifact,
		RequestedCapabilities: req.RequestedCapabilities,
		PolicyRef:             req.PolicyRef,
		Status:                api.SubmissionAccepted,
		CreatedAt:             time.Now().UTC(),
		ResultIDs:             []string{},
		DecisionID:            nil,
	}

	if s.dispatcher == nil {
		writeProblem(w, 500, "dispatch_error", "worker pool not configured")
		return
	}

	// Reserve capacity BEFORE writing the store so a full pool never creates
	// a submission (and never races abandon vs idempotent replay).
	token, err := s.dispatcher.Reserve(r.Context())
	if err != nil {
		if errors.Is(err, workers.ErrBackpressure) {
			writeBackpressure(w, "worker pool at capacity; retry later")
			return
		}
		if errors.Is(err, workers.ErrPoolClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "server is shutting down; retry later")
			return
		}
		writeProblem(w, 500, "dispatch_error", err.Error())
		return
	}
	committed := false
	defer func() {
		if !committed {
			token.Release()
		}
	}()

	fp := scintx.RequestFingerprint(req.SchemaVersion, req.Artifact, req.RequestedCapabilities, req.PolicyRef)
	accepted, created, err := s.store.PutSubmissionIdempotent(req.IdempotencyKey, fp, sub)
	if err != nil {
		if errors.Is(err, scintx.ErrIdempotencyConflict) {
			writeProblem(w, http.StatusConflict, "idempotency_conflict",
				"Idempotency-Key reused with a different request body")
			return
		}
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !created {
		// Replay — free the reserved slot; original job was already admitted.
		w.Header().Set("Location", "/v1/submissions/"+accepted.ID)
		writeJSON(w, 202, accepted)
		return
	}

	if err := token.Commit(accepted.ID); err != nil {
		s.abandonUnprocessed(accepted.ID, req.IdempotencyKey)
		if errors.Is(err, workers.ErrBackpressure) {
			writeBackpressure(w, "worker pool at capacity; retry later")
			return
		}
		if errors.Is(err, workers.ErrPoolClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "server is shutting down; retry later")
			return
		}
		writeProblem(w, 500, "dispatch_error", err.Error())
		return
	}
	committed = true

	w.Header().Set("Location", "/v1/submissions/"+accepted.ID)
	writeJSON(w, 202, accepted)
}

func (s *Server) getSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sub, ok, err := s.store.GetSubmission(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, 404, "not_found", "submission not found")
		return
	}
	writeJSON(w, 200, sub)
}

func (s *Server) listSubmissionResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok, err := s.store.GetSubmission(id); err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	} else if !ok {
		writeProblem(w, 404, "not_found", "submission not found")
		return
	}
	results, err := s.store.GetResultsForSubmission(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// getMergedResult returns the cross-provider aggregated finding view for a submission.
// 404 is returned when aggregation was not enabled for the submission (no aggregator
// was configured, or no providers returned findings to aggregate).
func (s *Server) getMergedResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Confirm the submission exists before checking for a merged result.
	if _, ok, err := s.store.GetSubmission(id); err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	} else if !ok {
		writeProblem(w, 404, "not_found", "submission not found")
		return
	}
	merged, ok, err := s.store.GetMergedResultForSubmission(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, 404, "not_found", "no merged result for submission "+id+
			"; aggregation may not be enabled or no findings were returned")
		return
	}
	writeJSON(w, 200, merged)
}

func (s *Server) getResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, ok, err := s.store.GetResult(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, 404, "not_found", "result not found")
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) getDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dec, ok, err := s.store.GetDecision(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, 404, "not_found", "decision not found")
		return
	}
	writeJSON(w, 200, dec)
}

func (s *Server) resumeSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.orchestrator.MarkForResume(id); err != nil {
		writeProblem(w, 409, "resume_failed", err.Error())
		return
	}
	if s.dispatcher == nil {
		_ = s.orchestrator.UnmarkResume(id)
		writeProblem(w, 500, "dispatch_error", "worker pool not configured")
		return
	}
	if err := s.dispatcher.Submit(r.Context(), id); err != nil {
		// Revert running → deferred so the client can retry resume later.
		_ = s.orchestrator.UnmarkResume(id)
		if errors.Is(err, workers.ErrBackpressure) {
			writeBackpressure(w, "worker pool at capacity; retry resume later")
			return
		}
		if errors.Is(err, workers.ErrPoolClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "server is shutting down; retry later")
			return
		}
		writeProblem(w, 500, "dispatch_error", err.Error())
		return
	}
	sub, ok, err := s.store.GetSubmission(id)
	if err != nil || !ok {
		writeProblem(w, 500, "store_error", "resume enqueued but submission missing")
		return
	}
	writeJSON(w, 202, sub)
}

// adjudicateSubmission records a consumer-shared final allow/deny resolution.
// Resolution happens in the system that plugs into SCINTX; this endpoint shares
// that outcome back so the gateway can store it and webhook subscribers.
func (s *Server) adjudicateSubmission(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	id := r.PathValue("id")
	var req api.AdjudicateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, 400, "invalid_request", err.Error())
		return
	}
	dec, err := s.orchestrator.Adjudicate(id, req)
	if err != nil {
		switch {
		case errors.Is(err, scintx.ErrAdjudicateNotFound):
			writeProblem(w, 404, "not_found", err.Error())
		case errors.Is(err, scintx.ErrAdjudicateInvalidDecision):
			writeProblem(w, 422, "invalid_adjudication", err.Error())
		case errors.Is(err, scintx.ErrAdjudicateInvalidState):
			writeProblem(w, 409, "adjudicate_conflict", err.Error())
		default:
			writeProblem(w, 500, "adjudicate_error", err.Error())
		}
		return
	}
	writeJSON(w, 201, dec)
}

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.Providers()
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	type providerSummary struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	out := make([]providerSummary, 0, len(providers))
	for _, p := range providers {
		var caps []string
		for _, c := range p.Capabilities.Capabilities {
			caps = append(caps, c.ID+":"+c.Version)
		}
		out = append(out, providerSummary{ID: p.ID, Name: p.Name, Capabilities: caps})
	}
	writeJSON(w, 200, map[string]any{"providers": out})
}

func (s *Server) getProviderCapabilities(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	caps, ok, err := s.store.GetCapabilities(id)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, 404, "not_found", "provider not found")
		return
	}
	writeJSON(w, 200, caps)
}

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	limit := maxArtifactBodyBytes()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader returns *http.MaxBytesError when the cap is hit.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "artifact_too_large",
				fmt.Sprintf("artifact exceeds max size of %d bytes", limit))
			return
		}
		writeProblem(w, 400, "invalid_request", "failed to read artifact body: "+err.Error())
		return
	}
	h := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(h[:])
	if err := s.store.PutArtifact(digest, body); err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	ref := api.ResourceReference{
		URI:       api.BlobURN(digest),
		MediaType: r.Header.Get("Content-Type"),
		Digests:   map[string]string{"sha256": hex.EncodeToString(h[:])},
	}
	writeJSON(w, 201, map[string]any{
		"artifact_ref": api.ArtifactRef{
			Digests:    map[string]string{"sha256": hex.EncodeToString(h[:])},
			ContentRef: &ref,
		},
	})
}

func (s *Server) checkArtifact(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	ok, err := s.store.HasArtifact(digest)
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	if ok {
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(404)
}

func (s *Server) wellKnown(w http.ResponseWriter, r *http.Request) {
	// Advertise only profiles that are actually enforced.
	profiles := []string{}
	if s.auth != nil {
		profiles = s.auth.Profiles()
	}
	writeJSON(w, 200, map[string]any{
		"standard": "scintx",
		"version":  "1.0.0",
		"endpoints": []string{
			"/v1/submissions",
			"/v1/results",
			"/v1/decisions",
			"/v1/providers",
			"/v1/artifacts",
			"/v1/events",
		},
		"auth_profiles": profiles,
		"event_types": []string{
			"submission.created", "submission.completed", "policy-decision.created",
			"policy-decision.resolved", "provider.invocation.started", "provider.result.completed",
		},
		"webhook": map[string]any{
			"content_type": "application/cloudevents+json",
			"digest":       "Content-Digest (RFC 9530 sha-256)",
			"signature":    "X-Scintx-Signature t=<unix>,v1=<hmac-sha256-hex>",
		},
	})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.Events()
	if err != nil {
		writeProblem(w, 500, "store_error", err.Error())
		return
	}
	subject := r.URL.Query().Get("subject")
	if subject != "" {
		filtered := make([]api.CloudEvent, 0, len(events))
		for _, e := range events {
			if e.Subject == subject {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}
	writeJSON(w, 200, map[string]any{"events": events})
}
