package scan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// pathDetector reports one finding per file it is handed, so the test can see
// exactly which files the walk read.
type pathDetector struct{}

func (pathDetector) Name() string           { return "path" }
func (pathDetector) Wants(path string) bool { return filepath.Ext(path) == ".go" }
func (pathDetector) Detect(f File) []model.Finding {
	return []model.Finding{{Asset: model.Asset{Algorithm: "MD5"}, Location: model.Location{File: f.Path, Line: 1}}}
}

func walkedFiles(t *testing.T, res *Result) []string {
	t.Helper()
	var got []string
	for _, f := range res.Findings {
		got = append(got, filepath.ToSlash(f.Location.File))
	}
	sort.Strings(got)
	return got
}

// Dependency and build output directories are not the operator's code and are
// not walked; files no detector wants are not read or counted; paths are
// reported relative to the root.
func TestScanSkipsVendoredTreesAndUnwantedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{
		"app/main.go",
		"vendor/lib/x.go",
		"node_modules/pkg/y.go",
		".git/hooks/z.go",
		"target/debug/w.go",
		"docs/readme.md",
	} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("package p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := New(pathDetector{}).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := walkedFiles(t, res)
	if len(got) != 1 || got[0] != "app/main.go" {
		t.Errorf("findings from %v, want only app/main.go", got)
	}
	if res.FilesWalked != 1 {
		t.Errorf("FilesWalked = %d, want 1: an unwanted file is not a walked one", res.FilesWalked)
	}
}

// A directory the walk cannot enter is counted as unreadable, and the rest of
// the tree is still scanned.
func TestScanCountsADirectoryItCannotEnter(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "hidden.go"), []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seen.go"), []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res, err := New(pathDetector{}).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unreadable != 1 {
		t.Errorf("Unreadable = %d, want 1 for the directory it could not enter", res.Unreadable)
	}
	if got := walkedFiles(t, res); len(got) != 1 || got[0] != "seen.go" {
		t.Errorf("findings from %v, want seen.go", got)
	}
}

// A root that does not exist is an error, not an empty scan.
func TestScanOfAMissingRootIsAnError(t *testing.T) {
	if _, err := New(pathDetector{}).Scan(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing root returned no error")
	}
}
