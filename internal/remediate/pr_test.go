package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	dirty    bool
	dirtyErr error
	base     string

	calls     []string
	branch    string
	added     []string
	commitMsg string
	pushed    string
	prTitle   string
	prBody    string
	prBase    string
	prURL     string
}

func (f *fakeRunner) Dirty(files []string) (bool, error) {
	f.calls = append(f.calls, "dirty")
	return f.dirty, f.dirtyErr
}
func (f *fakeRunner) BaseBranch() (string, error) {
	f.calls = append(f.calls, "base")
	if f.base == "" {
		return "main", nil
	}
	return f.base, nil
}
func (f *fakeRunner) CreateBranch(name string) error {
	f.calls = append(f.calls, "createBranch")
	f.branch = name
	return nil
}
func (f *fakeRunner) Add(files []string) error {
	f.calls = append(f.calls, "add")
	f.added = files
	return nil
}
func (f *fakeRunner) Commit(message string) error {
	f.calls = append(f.calls, "commit")
	f.commitMsg = message
	return nil
}
func (f *fakeRunner) Push(branch string) error {
	f.calls = append(f.calls, "push")
	f.pushed = branch
	return nil
}
func (f *fakeRunner) CreatePR(title, body, base string) (string, error) {
	f.calls = append(f.calls, "createPR")
	f.prTitle, f.prBody, f.prBase = title, body, base
	if f.prURL == "" {
		f.prURL = "https://github.com/acme/x/pull/1"
	}
	return f.prURL, nil
}

func samplePatches() []Patch {
	return []Patch{{
		File:       "weak.go",
		Rule:       "rsa-key-size",
		Rationale:  "raise sub-3072-bit RSA keys to 3072",
		Diff:       "--- a/weak.go\n+++ b/weak.go\n@@ -1,1 +1,1 @@\n-x\n+y\n",
		NewContent: "y\n",
	}}
}

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC) }
}

func TestOpenPRHappyPath(t *testing.T) {
	f := &fakeRunner{base: "main"}
	root := t.TempDir()
	url, err := OpenPR(root, samplePatches(), PROptions{now: fixedNow()}, f)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "weak.go")); string(got) != "y\n" {
		t.Errorf("patch not applied to disk: %q", got)
	}
	if url != "https://github.com/acme/x/pull/1" {
		t.Errorf("url=%q", url)
	}
	want := []string{"dirty", "base", "createBranch", "add", "commit", "push", "createPR"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Errorf("call order = %v, want %v", f.calls, want)
	}
	if f.branch != "qryx/fix-rsa-key-size-20260531090000" {
		t.Errorf("branch=%q", f.branch)
	}
	if f.pushed != f.branch {
		t.Errorf("pushed %q != branch %q", f.pushed, f.branch)
	}
	if f.prBase != "main" {
		t.Errorf("prBase=%q want main", f.prBase)
	}
	if len(f.added) != 1 || f.added[0] != "weak.go" {
		t.Errorf("added=%v", f.added)
	}
	if !strings.Contains(f.prBody, "raise sub-3072-bit RSA keys") || !strings.Contains(f.prBody, "```diff") {
		t.Errorf("PR body missing rationale/diff:\n%s", f.prBody)
	}
}

func TestOpenPRNoPatches(t *testing.T) {
	f := &fakeRunner{}
	if _, err := OpenPR(t.TempDir(), nil, PROptions{}, f); err == nil {
		t.Fatal("expected error for no patches")
	}
	if len(f.calls) != 0 {
		t.Errorf("no runner calls expected, got %v", f.calls)
	}
}

func TestOpenPRRefusesDirty(t *testing.T) {
	f := &fakeRunner{dirty: true}
	if _, err := OpenPR(t.TempDir(), samplePatches(), PROptions{}, f); err == nil {
		t.Fatal("expected error when working tree dirty")
	}
	for _, c := range f.calls {
		if c == "createBranch" {
			t.Fatal("must not create a branch when dirty")
		}
	}
}

func TestOpenPRCustomBranch(t *testing.T) {
	f := &fakeRunner{}
	if _, err := OpenPR(t.TempDir(), samplePatches(), PROptions{Branch: "my-branch"}, f); err != nil {
		t.Fatal(err)
	}
	if f.branch != "my-branch" {
		t.Errorf("branch=%q want my-branch", f.branch)
	}
}
