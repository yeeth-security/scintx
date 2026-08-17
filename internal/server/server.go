package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
)

type Server struct {
	Store        *scintx.Store
	Orchestrator *scintx.Orchestrator
	Emitter      *scintx.EventEmitter
	httpServer   *http.Server
}

func New(store *scintx.Store, orch *scintx.Orchestrator, emitter *scintx.EventEmitter) *Server {
	return &Server{Store: store, Orchestrator: orch, Emitter: emitter}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submissions", s.createSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}", s.getSubmission)
	mux.HandleFunc("POST /v1/submissions/{id}/resume", s.resumeSubmission)
	mux.HandleFunc("GET /v1/providers", s.listProviders)
	mux.HandleFunc("GET /v1/providers/{id}/capabilities", s.getProviderCapabilities)
	mux.HandleFunc("POST /v1/artifacts", s.uploadArtifact)
	mux.HandleFunc("HEAD /v1/artifacts/{digest}", s.checkArtifact)
	mux.HandleFunc("GET /v1/.well-known/scintx", s.wellKnown)
	mux.HandleFunc("GET /v1/events", s.listEvents)
	return mux
}

func (s *Server) Start(addr string) error {
	s.httpServer = &http.Server{Addr: addr, Handler: s.Routes()}
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(scintx.ProblemDetails{
		Type:   "https://scintx.example/problems/" + title,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

type createSubmissionRequest struct {
	SchemaVersion        string             `json:"schema_version"`
	Artifact             scintx.Artifact    `json:"artifact"`
	RequestedCapabilities []string          `json:"requested_capabilities,omitempty"`
	PolicyRef            *string            `json:"policy_ref,omitempty"`
	IdempotencyKey       string             `json:"-"`
}

func (s *Server) createSubmission(w http.ResponseWriter, r *http.Request) {
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
		cp, err := scintx.CanonicalPurl(*req.Artifact.PURL)
		if err != nil {
			writeProblem(w, 422, "invalid_purl", err.Error())
			return
		}
		req.Artifact.PURL = &cp
	}

	sub := &scintx.Submission{
		ID:                  "sub_" + scintx.RandHex(),
		SchemaVersion:       req.SchemaVersion,
		Artifact:            req.Artifact,
		RequestedCapabilities: req.RequestedCapabilities,
		PolicyRef:           req.PolicyRef,
		Status:              scintx.SubmissionAccepted,
		CreatedAt:           time.Now().UTC(),
		ResultIDs:           []string{},
		DecisionID:          nil,
	}
	s.Store.PutSubmission(sub)

	go s.Orchestrator.Process(context.Background(), sub)

	w.Header().Set("Location", "/v1/submissions/"+sub.ID)
	writeJSON(w, 202, sub)
}

func (s *Server) getSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sub, ok := s.Store.GetSubmission(id)
	if !ok {
		writeProblem(w, 404, "not_found", "submission not found")
		return
	}
	writeJSON(w, 200, sub)
}

func (s *Server) resumeSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Orchestrator.Resume(context.Background(), id); err != nil {
		writeProblem(w, 409, "resume_failed", err.Error())
		return
	}
	sub, _ := s.Store.GetSubmission(id)
	writeJSON(w, 200, sub)
}

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	providers := s.Store.Providers()
	type providerSummary struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	var out []providerSummary
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
	caps, ok := s.Store.GetCapabilities(id)
	if !ok {
		writeProblem(w, 404, "not_found", "provider not found")
		return
	}
	writeJSON(w, 200, caps)
}

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, r.ContentLength)
	n, _ := r.Body.Read(body)
	body = body[:n]
	h := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(h[:])
	s.Store.PutArtifact(digest, body)
	ref := scintx.ResourceReference{
		URI:       "urn:scintx:blob:" + digest,
		MediaType: r.Header.Get("Content-Type"),
		Digests:   map[string]string{"sha256": hex.EncodeToString(h[:])},
	}
	writeJSON(w, 201, map[string]any{"artifact_ref": scintx.ArtifactRef{Digests: map[string]string{"sha256": hex.EncodeToString(h[:])}, ContentRef: &ref}})
}

func (s *Server) checkArtifact(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if s.Store.HasArtifact(digest) {
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(404)
}

func (s *Server) wellKnown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"standard":            "scintx",
		"version":             "1.0.0",
		"endpoints":           []string{"/v1/submissions", "/v1/providers", "/v1/artifacts"},
		"auth_profiles":       []string{"rfc9421"},
		"event_types":         []string{"submission.created", "submission.completed", "policy-decision.created"},
	})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"events": s.Store.Events()})
}