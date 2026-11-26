package remediate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stageRunner fails at one named stage and records how far OpenPR got.
type stageRunner struct {
	fakeRunner
	failAt string
}

var errStage = errors.New("stage failed")

func (s *stageRunner) fail(stage string) error {
	if s.failAt == stage {
		return errStage
	}
	return nil
}
func (s *stageRunner) Dirty(files []string) (bool, error) {
	d, _ := s.fakeRunner.Dirty(files)
	return d, s.fail("dirty")
}
func (s *stageRunner) BaseBranch() (string, error) {
	b, _ := s.fakeRunner.BaseBranch()
	return b, s.fail("base")
}
func (s *stageRunner) CreateBranch(name string) error {
	_ = s.fakeRunner.CreateBranch(name)
	return s.fail("createBranch")
}
func (s *stageRunner) Add(files []string) error {
	_ = s.fakeRunner.Add(files)
	return s.fail("add")
}
func (s *stageRunner) Commit(msg string) error {
	_ = s.fakeRunner.Commit(msg)
	return s.fail("commit")
}
func (s *stageRunner) Push(branch string) error {
	_ = s.fakeRunner.Push(branch)
	return s.fail("push")
}
func (s *stageRunner) CreatePR(title, body, base string) (string, error) {
	u, _ := s.fakeRunner.CreatePR(title, body, base)
	if err := s.fail("createPR"); err != nil {
		return "", err
	}
	return u, nil
}

// Each stage's failure stops the sequence there, is returned wrapped with what
// was being done, and never yields a PR URL. A failure before the branch exists
// must not have written the patched file onto whatever branch was checked out.
func TestOpenPRStopsAtTheStageThatFailed(t *testing.T) {
	for _, tc := range []struct {
		stage, msg   string
		fileReplaced bool
	}{
		{"dirty", "check working tree", false},
		{"base", "resolve base branch", false},
		{"createBranch", "create branch", false},
		{"add", "stage files", true},
		{"commit", "commit", true},
		{"push", "push qryx/fix", true},
		{"createPR", "open PR", true},
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "weak.go"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := &stageRunner{failAt: tc.stage}
		url, err := OpenPR(root, samplePatches(), PROptions{now: fixedNow()}, r)
		if !errors.Is(err, errStage) || !strings.HasPrefix(err.Error(), tc.msg) {
			t.Errorf("%s: got %v, want an error starting %q wrapping the stage error", tc.stage, err, tc.msg)
		}
		if url != "" {
			t.Errorf("%s: a URL was returned from a failed run", tc.stage)
		}
		if last := r.calls[len(r.calls)-1]; last != tc.stage {
			t.Errorf("%s: OpenPR went on to %q after the failure", tc.stage, last)
		}
		got, _ := os.ReadFile(filepath.Join(root, "weak.go"))
		if (string(got) == "y\n") != tc.fileReplaced {
			t.Errorf("%s: file content %q, replaced=%v wanted", tc.stage, got, tc.fileReplaced)
		}
	}
}

// A patch whose file cannot be written stops before anything is staged.
func TestOpenPRStopsWhenAPatchCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	r := &stageRunner{}
	p := samplePatches()
	p[0].File = filepath.Join("missing-dir", "weak.go")
	_, err := OpenPR(root, p, PROptions{now: fixedNow()}, r)
	if err == nil || !strings.HasPrefix(err.Error(), "apply ") {
		t.Fatalf("got %v, want an apply error", err)
	}
	for _, c := range r.calls {
		if c == "add" {
			t.Fatal("files were staged after a patch failed to apply")
		}
	}
}

// Push sends the branch to origin, and a push with nowhere to go is an error
// that names the command and carries git's own message.
func TestGitCLIPushReachesOrigin(t *testing.T) {
	dir := gitRepo(t)
	var g GitCLI
	err := g.Push("main")
	if err == nil || !strings.Contains(err.Error(), "git push -u origin main") {
		t.Fatalf("push with no origin: got %v", err)
	}

	bare := filepath.Join(t.TempDir(), "origin.git")
	for _, args := range [][]string{{"init", "-q", "--bare", bare}, {"-C", dir, "remote", "add", "origin", bare}} {
		if _, err := run("git", args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Push("main"); err != nil {
		t.Fatal(err)
	}
	out, err := run("git", "-C", bare, "branch", "--list", "main")
	if err != nil || !strings.Contains(out, "main") {
		t.Errorf("origin has no main branch after the push: %q, %v", out, err)
	}
}

// CreatePR hands gh the title, body and base it was given and returns the URL
// gh prints, trimmed. A fake gh on PATH records the arguments.
func TestGitCLICreatePRPassesItsArgumentsToGH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake gh is a shell script")
	}
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\necho '  https://example.test/pr/7  '\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	url, err := GitCLI{}.CreatePR("the title", "the body", "release")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://example.test/pr/7" {
		t.Errorf("url = %q", url)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), "pr\ncreate\n--title\nthe title\n--body\nthe body\n--base\nrelease\n"; got != want {
		t.Errorf("gh got arguments %q, want %q", got, want)
	}

	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\necho 'not logged in' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (GitCLI{}).CreatePR("t", "b", "main"); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("a failing gh: got %v, want its stderr in the error", err)
	}
}
