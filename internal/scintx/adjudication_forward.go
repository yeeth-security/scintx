package scintx

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// ParseAdjudicationForwardAllowlist reads SCINTX_FORWARD_ADJUDICATIONS.
// Empty / unset = forwarding off. Comma-separated provider ids otherwise.
func ParseAdjudicationForwardAllowlist() map[string]struct{} {
	return parseAllowlist(os.Getenv("SCINTX_FORWARD_ADJUDICATIONS"))
}

func parseAllowlist(raw string) map[string]struct{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		out[id] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// WithAdjudicationForwarding enables anonymous adjudication fan-out to the
// listed provider ids (decision + PURL only). Empty map / nil disables.
func WithAdjudicationForwarding(allowlist map[string]struct{}) OrchestratorOption {
	return func(o *Orchestrator) {
		o.adjForward = allowlist
	}
}

// forwardAdjudicationBestEffort notifies opted-in providers asynchronously.
// Failures are logged; they never fail the consumer adjudication response.
func (o *Orchestrator) forwardAdjudicationBestEffort(sub *api.Submission, decision api.PolicyDecisionValue) {
	if len(o.adjForward) == 0 {
		return
	}
	if sub.Artifact.PURL == nil || strings.TrimSpace(*sub.Artifact.PURL) == "" {
		slog.Debug("adjudication forward skipped: no purl", "submission_id", sub.ID)
		return
	}
	feedback := api.AdjudicationFeedback{
		Decision: decision,
		PURL:     strings.TrimSpace(*sub.Artifact.PURL),
	}

	targets := o.adjudicationForwardTargets()
	if len(targets) == 0 {
		return
	}

	// Detach from the request: providers must not delay the HTTP response.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, p := range targets {
			recv, ok := p.(api.AdjudicationReceiver)
			if !ok {
				continue
			}
			if err := recv.ReceiveAdjudication(ctx, feedback); err != nil {
				slog.Warn("adjudication forward failed",
					"provider", p.ID(),
					"decision", string(feedback.Decision),
					"err", err,
				)
				continue
			}
			slog.Info("adjudication forwarded",
				"provider", p.ID(),
				"decision", string(feedback.Decision),
			)
		}
	}()
}

// adjudicationForwardTargets returns loaded providers that are on the allowlist,
// advertise AcceptsAdjudications, and implement AdjudicationReceiver.
func (o *Orchestrator) adjudicationForwardTargets() []api.Provider {
	var out []api.Provider
	for _, p := range o.providers {
		if _, ok := o.adjForward[p.ID()]; !ok {
			continue
		}
		if !p.Capabilities().AcceptsAdjudications {
			slog.Debug("adjudication forward skipped: capability flag off", "provider", p.ID())
			continue
		}
		if _, ok := p.(api.AdjudicationReceiver); !ok {
			slog.Debug("adjudication forward skipped: no AdjudicationReceiver", "provider", p.ID())
			continue
		}
		out = append(out, p)
	}
	return out
}
