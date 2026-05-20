package main

import "testing"

func TestParseOptionsAcceptsVersion(t *testing.T) {
	opts, err := parseOptions([]string{"--version"})
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if !opts.version {
		t.Fatalf("opts.version = false, want true")
	}
}
