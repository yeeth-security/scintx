package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestUploadArtifactTooLarge(t *testing.T) {
	t.Setenv("SCINTX_MAX_ARTIFACT_BYTES", "64")
	st := scintx.NewMemoryStore()
	srv := New(st, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/artifacts", bytes.NewReader(make([]byte, 128)))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var prob map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatal(err)
	}
	if prob["title"] != "artifact_too_large" {
		t.Fatalf("problem=%v", prob)
	}
}

func TestUploadArtifactOK(t *testing.T) {
	t.Setenv("SCINTX_MAX_ARTIFACT_BYTES", "1024")
	st := scintx.NewMemoryStore()
	srv := New(st, nil, nil, nil)

	payload := []byte("vsix-bytes")
	req := httptest.NewRequest(http.MethodPost, "/v1/artifacts", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("status=%d body=%s", rr.Code, body)
	}
}

func TestMaxArtifactBodyBytesDefault(t *testing.T) {
	os.Unsetenv("SCINTX_MAX_ARTIFACT_BYTES")
	if got := maxArtifactBodyBytes(); got != defaultMaxArtifactBody {
		t.Fatalf("got=%d want=%d", got, defaultMaxArtifactBody)
	}
	t.Setenv("SCINTX_MAX_ARTIFACT_BYTES", "not-a-number")
	if got := maxArtifactBodyBytes(); got != defaultMaxArtifactBody {
		t.Fatalf("invalid env got=%d want default", got)
	}
}
