package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// countingDetector wants every .go file and finds nothing in any of them: the
// walker's counters are about what reached a detector, not about what a
// detector concluded. It reports a file whose content says so as unparsable,
// the way goast reports a Go file that does not parse.
type countingDetector struct{ unparsed int }

func (c *countingDetector) Name() string { return "counting" }

func (c *countingDetector) Wants(path string) bool { return filepath.Ext(path) == ".go" }

func (c *countingDetector) Detect(f File) []model.Finding {
	if strings.Contains(string(f.Content), "does not parse") {
		c.unparsed++
	}
	return nil
}

func (c *countingDetector) Unparsed() int { return c.unparsed }

// Every read or parse failure in the walk used to be a bare `return nil`, and
// FilesWalked only counted the files that survived all of them. A tree qryx
// could not open produced the same "0 findings" as a tree with no crypto in it,
// and the summary line had no way to reveal the difference.
func TestScanCountsWhatItCouldNotExamine(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return full
	}

	write("good.go", "package p\n", 0o600)
	write("broken.go", "package p // does not parse\n", 0o600)

	// One byte over the cap. Truncate leaves the file sparse, so this costs no
	// real bytes and the test still drives the real constant.
	big, err := os.Create(filepath.Join(dir, "big.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := big.Close(); err != nil {
		t.Fatal(err)
	}

	// A file the walker is allowed to see and not to read. Root ignores the
	// mode bits, so that half of the assertion only runs where it means
	// something.
	write("locked.go", "package p\n", 0o000)
	wantUnreadable, wantWalked := 1, 2
	if os.Geteuid() == 0 {
		wantUnreadable, wantWalked = 0, 3
	}

	res, err := New(&countingDetector{}).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	if res.Oversize != 1 {
		t.Errorf("Oversize = %d, want 1: a file skipped for its size is not a file with no crypto in it", res.Oversize)
	}
	if res.Unreadable != wantUnreadable {
		t.Errorf("Unreadable = %d, want %d", res.Unreadable, wantUnreadable)
	}
	if res.Unparsed != 1 {
		t.Errorf("Unparsed = %d, want 1", res.Unparsed)
	}
	if res.FilesWalked != wantWalked {
		t.Errorf("FilesWalked = %d, want %d", res.FilesWalked, wantWalked)
	}
}

// The counters have to be zero on a tree that was read in full, or the operator
// learns to ignore them.
func TestScanOfAReadableTreeCountsNothingUnexamined(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res, err := New(&countingDetector{}).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unreadable != 0 || res.Oversize != 0 || res.Unparsed != 0 {
		t.Errorf("clean tree reported unreadable=%d oversize=%d unparsed=%d, want all zero",
			res.Unreadable, res.Oversize, res.Unparsed)
	}
	if res.FilesWalked != 2 {
		t.Errorf("FilesWalked = %d, want 2", res.FilesWalked)
	}
}

// A Scanner used twice must report the second scan's failures, not the sum of
// both: the detectors carry the count and they outlive a single walk.
func TestScanDoesNotInheritTheUnparsedCountOfAnEarlierScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package p // does not parse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "ok.go"), []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(&countingDetector{})
	if _, err := s.Scan(dir); err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(clean)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unparsed != 0 {
		t.Errorf("Unparsed = %d on a clean tree, want 0: the count carried over from the previous scan", res.Unparsed)
	}
}
