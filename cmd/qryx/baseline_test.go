package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A baseline that is not there is not the same result as a baseline with no
// drift against it, and until 2026-08-05 qryx could not tell them apart. Both
// produced an empty delta: `--fail-on-new` iterated nothing and passed, and
// `--policy --policy-new-only` evaluated an empty node set, found zero
// violations and exited 0. A typo in a CI path, a cache miss, or a first run on
// a new branch turned a blocking gate into a green build, and the only thing
// that said so was a warning on stderr that no CI system reads.
//
// So these tests are not about drift. They are about a gate that cannot report
// success when it never compared anything.
func TestMissingBaselineFailsTheFailOnNewGate(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-baseline.json")

	var err error
	captureOutput(t, func() {
		err = run([]string{"scan", "--baseline", missing, "--fail-on-new", "high", dir})
	})

	if err == nil {
		t.Fatal("--fail-on-new returned nil with no baseline to compare against: the gate passed without ever looking")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the baseline path, so nobody can see which path was wrong", err)
	}
}

// The same hole under the other gate that reads the drift result.
func TestMissingBaselineFailsThePolicyNewOnlyGate(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-baseline.json")

	var err error
	captureOutput(t, func() {
		err = run([]string{"scan", "--policy", "cnsa", "--baseline", missing, "--policy-new-only", dir})
	})

	if err == nil {
		t.Fatal("--policy --policy-new-only returned nil with no baseline: the policy was enforced against an empty set of new assets")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the baseline path, so nobody can see which path was wrong", err)
	}
}

// The legitimate first run: there is genuinely no baseline yet and the operator
// says so. That has to stay a pass, or the gate cannot be adopted at all.
func TestAllowMissingBaselineKeepsTheFirstRunGreen(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-baseline.json")

	var err error
	_, stderr := captureOutput(t, func() {
		err = run([]string{"scan", "--baseline", missing, "--fail-on-new", "high", "--allow-missing-baseline", dir})
	})

	if err != nil {
		t.Fatalf("--allow-missing-baseline returned %v, want nil: an explicit first run must still pass", err)
	}
	if !strings.Contains(stderr, missing) {
		t.Errorf("stderr %q does not say the baseline was missing; the pass has to be visible, not silent", stderr)
	}
}

// Without a gate flag there is nothing to fail open: --baseline alone only
// reports drift, so a missing one stays a warning and an exit 0.
func TestMissingBaselineWithoutAGateStillOnlyWarns(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-baseline.json")

	var err error
	_, stderr := captureOutput(t, func() {
		err = run([]string{"scan", "--baseline", missing, dir})
	})

	if err != nil {
		t.Fatalf("run(scan --baseline <missing>) returned %v, want nil: no gate depends on it here", err)
	}
	if !strings.Contains(stderr, missing) {
		t.Errorf("stderr %q does not name the missing baseline", stderr)
	}
}

// captureOutput runs fn with both standard streams redirected and returns what
// it wrote to each. run() reports to stderr and formats to stdout, and a test
// that asserts on one must not spray the other over the suite's output.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = savedOut, savedErr }()

	fn()

	read := func(w *os.File, r *os.File) string {
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		buf := make([]byte, 64<<10)
		n, _ := r.Read(buf)
		return string(buf[:n])
	}
	return read(outW, outR), read(errW, errR)
}
