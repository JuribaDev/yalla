package main

import (
	"os"
	"strings"
	"testing"
)

func TestMainDoesNotWireNoopJobEnqueuer(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(src), "noopJobEnqueuer") {
		t.Fatal("cmd/yalla-api must wire jobs.NewEnqueuer, not noopJobEnqueuer")
	}
}

func TestMainWiresConfiguredInternalWorkerToken(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(src), "InternalWorkerToken: cfg.InternalWorkerToken") {
		t.Fatal("cmd/yalla-api must pass cfg.InternalWorkerToken into auth.AuthenticatorConfig")
	}
}
