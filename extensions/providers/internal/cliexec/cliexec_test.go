package cliexec_test

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/extensions/providers/internal/cliexec"
)

func TestClassifyTimeoutFromScanCtx(t *testing.T) {
	scanCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-scanCtx.Done()

	err := cliexec.Classify("skillspector", errors.New("signal: killed"), scanCtx, context.Background(), 0, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestClassifyKilledWithoutDeadline(t *testing.T) {
	err := cliexec.Classify(
		"skillspector",
		errors.New("signal: killed"),
		context.Background(),
		context.Background(),
		0,
		"",
	)
	var killed *cliexec.KilledError
	if !errors.As(err, &killed) {
		t.Fatalf("expected KilledError, got %v", err)
	}
}

func TestClassifyFindingsExitOk(t *testing.T) {
	// Non-zero exit with stdout is "findings found" for these CLIs.
	err := cliexec.Classify(
		"grype",
		&exec.ExitError{},
		context.Background(),
		context.Background(),
		128,
		"",
	)
	if err != nil {
		t.Fatalf("expected nil for exit+stdout, got %v", err)
	}
}
