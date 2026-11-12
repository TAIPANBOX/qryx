package main

import (
	"strings"
	"testing"
)

// `qryx ssh` is a subcommand like `qryx tls`: it needs a target, and a target
// that refuses the connection is reported and skipped rather than failing the
// whole run, so one dead host cannot hide the rest of an inventory.
func TestSSHSubcommandIsWired(t *testing.T) {
	err := run([]string{"ssh"})
	if err == nil || !strings.Contains(err.Error(), "ssh requires at least one host:port target") {
		t.Fatalf("qryx ssh with no target: %v", err)
	}
	if err := run([]string{"ssh", "-timeout", "300ms", "127.0.0.1:1"}); err != nil {
		t.Fatalf("a target that refuses must be reported and skipped, not fail the run: %v", err)
	}
}
