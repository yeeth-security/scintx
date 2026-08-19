package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

func TestHTTPDelivererPostsSignedEvent(t *testing.T) {
	var (
		mu       sync.Mutex
		gotBody  []byte
		gotHdr   http.Header
		received = make(chan struct{}, 1)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = append([]byte(nil), body...)
		gotHdr = r.Header.Clone()
		mu.Unlock()
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	secret := []byte("test-secret")
	d := &HTTPDeliverer{
		URL:         srv.URL,
		Secret:      secret,
		HTTPClient:  srv.Client(),
		MaxAttempts: 1,
		sem:         make(chan struct{}, 8),
	}
	evt := api.CloudEvent{
		SpecVersion: "1.0",
		ID:          "evt_test",
		Source:      "https://scintx.example",
		Type:        "org.eclipse.scintx.submission.completed.v1",
		Subject:     "sub_1",
		Time:        time.Now().UTC(),
		Data:        map[string]any{"submission_id": "sub_1"},
	}
	d.Deliver(evt)

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not received")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotHdr.Get("Content-Type") != "application/cloudevents+json" {
		t.Fatalf("content-type=%s", gotHdr.Get("Content-Type"))
	}
	if gotHdr.Get("Content-Digest") == "" {
		t.Fatal("missing Content-Digest")
	}
	if err := VerifySignature(secret, gotHdr.Get("X-Scintx-Signature"), gotBody, time.Minute); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var decoded api.CloudEvent
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != evt.ID || decoded.Type != evt.Type {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestConfigRequiresSecret(t *testing.T) {
	t.Setenv("SCINTX_WEBHOOK_URL", "http://example.invalid/hook")
	t.Setenv("SCINTX_WEBHOOK_SECRET", "")
	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatal("expected error when secret missing")
	}
}

func TestOpenNilWhenEmpty(t *testing.T) {
	d, err := Open(Config{})
	if err != nil || d != nil {
		t.Fatalf("want nil deliverer, got %#v err=%v", d, err)
	}
}
