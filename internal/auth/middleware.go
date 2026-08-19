package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// Verifier checks inbound requests according to Config.
type Verifier struct {
	cfg Config
}

// NewVerifier builds a verifier. Returns nil when auth is disabled.
func NewVerifier(cfg Config) *Verifier {
	if !cfg.Enabled() {
		return nil
	}
	return &Verifier{cfg: cfg}
}

// Profiles returns enabled profile names for discovery.
func (v *Verifier) Profiles() []string {
	if v == nil {
		return nil
	}
	out := make([]string, len(v.cfg.Profiles))
	copy(out, v.cfg.Profiles)
	return out
}

// Middleware enforces auth on all routes except well-known discovery.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	if v == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := readBody(r)
		if err != nil {
			writeAuthProblem(w, http.StatusBadRequest, "invalid_request", "failed to read body")
			return
		}
		if err := v.verify(r, body); err != nil {
			writeAuthProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *Verifier) verify(r *http.Request, body []byte) error {
	var errs []string
	for _, p := range v.cfg.Profiles {
		switch p {
		case ProfileHMAC:
			if err := verifyHMAC(v.cfg, r, body); err == nil {
				return nil
			} else {
				errs = append(errs, "hmac: "+err.Error())
			}
		case ProfileBearer:
			if err := verifyBearer(v.cfg, r); err == nil {
				return nil
			} else {
				errs = append(errs, "bearer: "+err.Error())
			}
		}
	}
	if len(errs) == 0 {
		return fmtError("no auth profile configured")
	}
	return fmtError(strings.Join(errs, "; "))
}

func fmtError(s string) error { return &authError{s} }

type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

func isPublicPath(path string) bool {
	return path == "/v1/.well-known/scintx" || path == "/.well-known/scintx"
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 33<<20))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func writeAuthProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("WWW-Authenticate", `HMAC-SHA256 realm="scintx", Bearer realm="scintx"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.ProblemDetails{
		Type:   "https://scintx.example/problems/" + title,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}
