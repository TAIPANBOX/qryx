package agentstack

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func copyFixture(t *testing.T, dst, name string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func basenames(t *testing.T, path string) []string {
	t.Helper()
	got := mustScan(t, path)
	var names []string
	for _, f := range got {
		names = append(names, filepath.Base(f.Location.File))
	}
	sort.Strings(names)
	return names
}

// A glob names exactly the files it matches, and a directory among the matches
// is walked: `qryx agents 'fleet/*'` must see the passports in each team's
// directory, not just the files at the top.
func TestScanExpandsAGlobAndWalksMatchedDirectories(t *testing.T) {
	root := t.TempDir()
	copyFixture(t, filepath.Join(root, "a-passport.json"), "passport-spiffe.json")
	copyFixture(t, filepath.Join(root, "team", "nested", "events.ndjson"), "events-chained.ndjson")
	copyFixture(t, filepath.Join(root, "other.txt"), "passport-none.json")

	got := basenames(t, filepath.Join(root, "*-passport.json"))
	if len(got) != 1 || got[0] != "a-passport.json" {
		t.Errorf("a glob for one file gave %v", got)
	}

	got = basenames(t, filepath.Join(root, "te?m"))
	if len(got) != 1 || got[0] != "events.ndjson" {
		t.Errorf("a glob matching a directory did not walk it: %v", got)
	}

	got = basenames(t, filepath.Join(root, "*"))
	if len(got) != 3 {
		t.Errorf("a glob over everything gave %v, want all three files", got)
	}

	if got := basenames(t, filepath.Join(root, "*.nothing")); len(got) != 0 {
		t.Errorf("a glob matching nothing gave %v", got)
	}
}

// A malformed pattern and a path that does not exist are errors, never an
// empty inventory that reads as "no agents".
func TestScanRefusesABadPatternAndAMissingPath(t *testing.T) {
	if _, err := Scan("[unclosed"); err == nil {
		t.Error("a malformed glob returned no error")
	}
	if _, err := Scan(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing path returned no error")
	}
	got := basenames(t, filepath.Join("testdata", "passport-spiffe.json"))
	if len(got) != 1 {
		t.Errorf("a single file gave %v", got)
	}
}

// One file that cannot be read is skipped and the rest are still scanned.
func TestScanSkipsAnUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file modes do not deny reads here")
	}
	root := t.TempDir()
	copyFixture(t, filepath.Join(root, "ok.json"), "passport-spiffe.json")
	copyFixture(t, filepath.Join(root, "locked.json"), "passport-none.json")
	if err := os.Chmod(filepath.Join(root, "locked.json"), 0); err != nil {
		t.Fatal(err)
	}
	got := basenames(t, root)
	if len(got) != 1 || got[0] != "ok.json" {
		t.Errorf("got %v, want only the readable passport", got)
	}
}
