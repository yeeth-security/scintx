package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
	"github.com/yeeth-security/scintx/internal/workers"
)

func stressScale() int {
	n, err := strconv.Atoi(os.Getenv("SCINTX_STRESS_SCALE"))
	if err != nil || n < 1 {
		return 1
	}
	if n > 20 {
		return 20
	}
	return n
}

// TestStressE2E_HTTPBackpressureAndCompletion floods submissions against a
// small worker pool and asserts every request ends in 202 or 429, with all
// accepted submissions eventually completing.
func TestStressE2E_HTTPBackpressureAndCompletion(t *testing.T) {
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	scale := stressScale()
	requests := 80 * scale

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatal(err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatal(err)
	}

	srv := server.New(store, orch, emitter, nil)
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeLocal, Workers: 4, MaxInflight: 8,
	}, srv.RootContext(), orch.Process)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = disp.Close()
		disp.Wait()
	})
	srv.SetDispatcher(disp)

	var (
		accepted atomic.Int64
		rejected atomic.Int64
		other    atomic.Int64
		ids      sync.Map
	)

	var wg sync.WaitGroup
	wg.Add(requests)
	for i := 0; i < requests; i++ {
		i := i
		go func() {
			defer wg.Done()
			body := map[string]any{
				"schema_version": "1.0.0",
				"artifact": map[string]any{
					"purl": fmt.Sprintf("pkg:pypi/clean-package@1.0.%d", i),
				},
				"requested_capabilities": []string{"vulnerability"},
				"policy_ref":             "registry-default",
			}
			// Retry briefly on 429 so we still measure pressure, then give up.
			for attempt := 0; attempt < 40; attempt++ {
				var buf bytes.Buffer
				_ = json.NewEncoder(&buf).Encode(body)
				req := httptest.NewRequest("POST", "/v1/submissions", &buf)
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				srv.Routes().ServeHTTP(rr, req)
				switch rr.Code {
				case http.StatusAccepted:
					accepted.Add(1)
					var sub api.Submission
					_ = json.Unmarshal(rr.Body.Bytes(), &sub)
					ids.Store(sub.ID, true)
					return
				case http.StatusTooManyRequests:
					if rr.Header().Get("Retry-After") == "" {
						t.Errorf("429 missing Retry-After")
					}
					rejected.Add(1)
					time.Sleep(2 * time.Millisecond)
				default:
					other.Add(1)
					t.Errorf("unexpected status %d: %s", rr.Code, rr.Body.String())
					return
				}
			}
			// Exhausted retries — count as pressure, not failure of invariants.
		}()
	}
	wg.Wait()

	if accepted.Load() == 0 {
		t.Fatal("expected some 202 accepts")
	}
	if rejected.Load() == 0 {
		t.Fatal("expected some 429 backpressure under MaxInflight=8")
	}
	if other.Load() != 0 {
		t.Fatalf("unexpected statuses: %d", other.Load())
	}

	// Wait for accepted submissions to complete.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		pending := 0
		ids.Range(func(k, _ any) bool {
			sub, ok, err := store.GetSubmission(k.(string))
			if err != nil || !ok {
				pending++
				return true
			}
			if sub.Status != api.SubmissionCompleted && sub.Status != api.SubmissionFailed {
				pending++
			}
			return true
		})
		if pending == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	var incomplete int
	ids.Range(func(k, _ any) bool {
		sub, ok, _ := store.GetSubmission(k.(string))
		if !ok || (sub.Status != api.SubmissionCompleted && sub.Status != api.SubmissionFailed) {
			incomplete++
		}
		return true
	})
	if incomplete > 0 {
		t.Fatalf("%d accepted submissions did not finish", incomplete)
	}

	t.Logf("http stress: accepted=%d rejected_429=%d", accepted.Load(), rejected.Load())
}

// TestStressE2E_QueueModeMultiWorkerHTTP drives queue mode with concurrent HTTP
// admits and two claim workers sharing one store.
func TestStressE2E_QueueModeMultiWorkerHTTP(t *testing.T) {
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	scale := stressScale()
	requests := 40 * scale

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatal(err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := server.New(store, orch, emitter, nil)
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 4, MaxInflight: 16,
		Lease: 5 * time.Second, PollInterval: 10 * time.Millisecond,
		MaxPending: 200, MaxAttempts: 8,
	}, ctx, orch.Process, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = disp.Close()
		cancel()
		disp.Wait()
	})
	srv.SetDispatcher(disp)

	var accepted atomic.Int64
	var ids sync.Map
	var wg sync.WaitGroup
	wg.Add(requests)
	for i := 0; i < requests; i++ {
		i := i
		go func() {
			defer wg.Done()
			rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
				"schema_version": "1.0.0",
				"artifact": map[string]any{
					"purl": fmt.Sprintf("pkg:pypi/clean-package@2.0.%d", i),
				},
				"requested_capabilities": []string{"vulnerability"},
				"policy_ref":             "registry-default",
			})
			if rr.Code != 202 {
				t.Errorf("want 202, got %d %s", rr.Code, rr.Body.String())
				return
			}
			accepted.Add(1)
			var sub api.Submission
			_ = json.Unmarshal(rr.Body.Bytes(), &sub)
			ids.Store(sub.ID, true)
		}()
	}
	wg.Wait()

	if accepted.Load() != int64(requests) {
		t.Fatalf("accepted=%d want %d", accepted.Load(), requests)
	}

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		pending := 0
		ids.Range(func(k, _ any) bool {
			sub, ok, _ := store.GetSubmission(k.(string))
			if !ok || sub.Status != api.SubmissionCompleted {
				pending++
			}
			return true
		})
		if pending == 0 {
			t.Logf("queue http stress: completed %d submissions", requests)
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("timed out waiting for queue-mode completions")
}
