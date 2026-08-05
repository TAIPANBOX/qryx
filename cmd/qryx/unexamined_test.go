package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/scan"
)

// "0 findings" and "could not look" print the same line, and until 2026-08-05
// they printed it for the same scan. The walker returned nil for a directory
// entry it could not read, for a file whose Info() failed, for a file over the
// size cap and for a file whose read failed, and FilesWalked only counted the
// files that survived all four, so nothing downstream could tell a tree with no
// crypto in it from a tree qryx never opened.
//
// The operator-visible half of the fix is asserted here: the summary has to say
// so on stderr, next to the test-code exclusion line, or the count exists and
// nobody sees it.
func TestScanReportsFilesItCouldNotExamine(t *testing.T) {
	dir := t.TempDir()

	// A file the goast detector wants and the walker must refuse: one byte over
	// the size cap. Truncate keeps it sparse, so this costs no real bytes.
	big, err := os.Create(filepath.Join(dir, "big.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(scan.MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := big.Close(); err != nil {
		t.Fatal(err)
	}

	var runErr error
	_, stderr := captureOutput(t, func() {
		runErr = run([]string{"scan", dir})
	})
	if runErr != nil {
		t.Fatalf("run(scan) returned %v, want nil: a file it cannot examine is not a fatal error", runErr)
	}

	if !strings.Contains(stderr, "not examined") {
		t.Errorf("stderr %q never says a file went unexamined, so a scan that could not look reads exactly like a clean one", stderr)
	}
	if !strings.Contains(stderr, "size cap") {
		t.Errorf("stderr %q does not say why the file was skipped", stderr)
	}
}

// The other half: a tree qryx could read in full must not print the line at
// all, or it becomes noise an operator learns to skip past.
func TestCleanScanSaysNothingAboutUnexaminedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.go"), []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr := captureOutput(t, func() {
		if err := run([]string{"scan", dir}); err != nil {
			t.Fatalf("run(scan) returned %v, want nil", err)
		}
	})
	if strings.Contains(stderr, "not examined") {
		t.Errorf("stderr %q reports unexamined files for a tree that was read in full", stderr)
	}
}
