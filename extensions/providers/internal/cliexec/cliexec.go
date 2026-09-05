// Package cliexec classifies subprocess failures from local CLI scanners
// (SkillSpector, GuardDog, Grype, …).
//
// exec.CommandContext SIGKILLs the child when the deadline fires. That surfaces
// as "signal: killed" without wrapping context.DeadlineExceeded, so callers
// must check the scan context after cmd.Run and map killed/OOM distinctly
// from ordinary transport failures.
package cliexec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Classify turns a cmd.Run error into a typed failure for provider result mapping.
//
// scanCtx is the context passed to CommandContext (with timeout). parentCtx is
// the Assess context (may already be cancelled by the orchestrator).
func Classify(name string, err error, scanCtx, parentCtx context.Context, stdoutLen int, stderr string) error {
	if err == nil {
		return nil
	}

	// Timeout: CommandContext cancelled the child — prefer this over "killed".
	if errors.Is(scanCtx.Err(), context.DeadlineExceeded) ||
		errors.Is(parentCtx.Err(), context.DeadlineExceeded) ||
		errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", name, context.DeadlineExceeded)
	}
	if scanCtx.Err() != nil {
		return fmt.Errorf("%s: %w", name, scanCtx.Err())
	}
	if parentCtx.Err() != nil {
		return fmt.Errorf("%s: %w", name, parentCtx.Err())
	}

	if errors.Is(err, exec.ErrNotFound) ||
		strings.Contains(err.Error(), "executable file not found") ||
		strings.Contains(err.Error(), "no such file or directory") {
		return fmt.Errorf("%s: binary not found", name)
	}

	// Non-zero exit with stdout is often "findings found" for these tools.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdoutLen > 0 && !isKilled(err) {
		return nil
	}

	if isKilled(err) {
		// SIGKILL without a cancelled context — almost always the OOM killer
		// (or an external cgroup limit) on Cloud Run / containers.
		return &KilledError{
			Name: name,
			Err:  err,
			Hint: "process was SIGKILL'd (likely out of memory); raise container memory or lower concurrency",
		}
	}

	if stdoutLen == 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			return fmt.Errorf("%s exited: %v", name, err)
		}
		return fmt.Errorf("%s exited: %v, stderr: %s", name, err, truncate(msg, 400))
	}

	// Had stdout but also a hard failure we couldn't classify — still surface it.
	return fmt.Errorf("%s exited: %v", name, err)
}

// KilledError means the CLI was SIGKILL'd without a context deadline (OOM / cgroup).
type KilledError struct {
	Name string
	Err  error
	Hint string
}

func (e *KilledError) Error() string {
	return fmt.Sprintf("%s: %s (%v)", e.Name, e.Hint, e.Err)
}

func (e *KilledError) Unwrap() error { return e.Err }

func isKilled(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "signal: killed") ||
		(strings.Contains(msg, "killed") && strings.Contains(msg, "signal"))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
