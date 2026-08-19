package webhook

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// TestHTTPDeliverer_BacklogDropsUnderLoad fills the concurrency semaphore and
// asserts Deliver does not hang (drops excess events).
func TestHTTPDeliverer_BacklogDropsUnderLoad(t *testing.T) {
	var received atomic.Int32
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		<-block
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	d := &HTTPDeliverer{
		URL:         srv.URL,
		Secret:      []byte("secret"),
		HTTPClient:  srv.Client(),
		MaxAttempts: 1,
		sem:         make(chan struct{}, 1), // tiny backlog
		log:         slog.Default(),
	}

	for i := 0; i < 20; i++ {
		d.Deliver(api.CloudEvent{
			SpecVersion: "1.0",
			ID:          "evt_drop_" + string(rune('a'+i%26)),
			Source:      "https://scintx.example",
			Type:        "org.eclipse.scintx.submission.completed.v1",
			Time:        time.Now().UTC(),
		})
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for received.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if received.Load() < 1 {
		t.Fatal("expected at least one delivery to start")
	}
	close(block)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = d.Close(ctx)
	if received.Load() > 8 {
		t.Fatalf("expected backlog drops; received=%d", received.Load())
	}
}
