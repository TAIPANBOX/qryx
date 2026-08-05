package main

import (
	"os"
	"strings"
	"testing"
)

// The release assets are named without a version on purpose, so that
// releases/latest/download/<name> is a permanent address. The version does not
// disappear: it moves into the binary. That is only true if the binary can be
// asked, and before 2026-08-05 it could not. `qryx version` was in the README,
// was not in the command allowlist, and exited 1 with "unknown command".
//
// So this test is not about a subcommand. It is about the one thing that makes
// version-less asset names honest rather than merely convenient.
func TestVersionCommandPrintsTheStampedVersion(t *testing.T) {
	version = "v9.9.9-test"
	t.Cleanup(func() { version = "dev" })

	out := captureStdout(t, func() {
		if err := run([]string{"version"}); err != nil {
			t.Fatalf("run(version) returned %v, want nil", err)
		}
	})

	if !strings.Contains(out, "v9.9.9-test") {
		t.Errorf("stdout %q does not carry the stamped version", out)
	}
	if !strings.HasPrefix(out, "qryx ") {
		t.Errorf("stdout %q does not name the tool, so a log line cannot say what reported it", out)
	}
}

// Answering `version` must not depend on the rest of the command line parsing,
// because the reason to ask is often that you do not know how this build
// behaves. A flag the binary has never heard of must not stop it identifying
// itself.
func TestVersionIgnoresAnUnknownFlagAfterIt(t *testing.T) {
	version = "v9.9.9-test"
	t.Cleanup(func() { version = "dev" })

	out := captureStdout(t, func() {
		if err := run([]string{"version", "--not-a-real-flag"}); err != nil {
			t.Fatalf("run(version, --not-a-real-flag) returned %v, want nil", err)
		}
	})
	if !strings.Contains(out, "v9.9.9-test") {
		t.Errorf("stdout %q does not carry the stamped version", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
