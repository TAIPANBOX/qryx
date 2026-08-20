package remediate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GitCLI is the production Runner and none of it had ever been run. It is
// eight thin wrappers, and thin is exactly why: nothing here looks worth a
// test until one of them is scoped wrongly.
//
// The scoping is the part with consequences. `qryx fix` asks Dirty whether the
// files IT is about to change are already modified, and stops if they are. A
// Dirty that answers about the whole tree instead refuses to run in any
// repository where somebody has an unrelated edit open, which is most of them,
// and the failure looks like a broken tool rather than a wrong answer.
//
// These run against a real git repository rather than a stub, because a stub
// would be asserting my reading of `git status --porcelain` rather than git's
// behaviour, and the reading is the part that could be wrong.

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "test@qryx.invalid"},
		{"config", "user.name", "qryx test"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	write(t, dir, "a.txt", "one\n")
	write(t, dir, "b.txt", "two\n")
	for _, args := range [][]string{
		{"add", "-A"},
		{"commit", "-qm", "initial"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	t.Chdir(dir)
	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The one that decides whether `qryx fix` will run at all.
func TestDirtyAnswersAboutTheFilesItWasAskedAbout(t *testing.T) {
	dir := gitRepo(t)
	var g GitCLI

	dirty, err := g.Dirty([]string{"a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if dirty {
		t.Fatal("a freshly committed file reads as modified")
	}

	// Somebody has an unrelated edit open, which is the normal state of a
	// working repository.
	write(t, dir, "b.txt", "two, edited\n")

	dirty, err = g.Dirty([]string{"a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if dirty {
		t.Fatal("an edit to b.txt made a.txt read as modified. qryx fix would " +
			"refuse to run in any repository with an unrelated change open, " +
			"and the failure would look like a broken tool rather than a " +
			"wrong answer")
	}

	dirty, err = g.Dirty([]string{"b.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !dirty {
		t.Fatal("an edited file did not read as modified: qryx fix would " +
			"overwrite somebody's uncommitted work and commit it as its own")
	}
}

// A file that is not tracked at all still counts as something in the way.
func TestDirtySeesAnUntrackedFile(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "new.txt", "not committed anywhere\n")

	dirty, err := GitCLI{}.Dirty([]string{"new.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !dirty {
		t.Fatal("an untracked file reads as clean, so a fix would write over " +
			"a file git has never seen and the operator would lose it")
	}
}

func TestBranchesAreCreatedAndReported(t *testing.T) {
	gitRepo(t)
	var g GitCLI

	base, err := g.BaseBranch()
	if err != nil {
		t.Fatal(err)
	}
	if base != "main" {
		t.Fatalf("BaseBranch = %q, want main: a PR opened against the wrong "+
			"base is a PR nobody can merge", base)
	}

	if err := g.CreateBranch("qryx/fix-rsa-2048"); err != nil {
		t.Fatal(err)
	}
	now, err := g.BaseBranch()
	if err != nil {
		t.Fatal(err)
	}
	if now != "qryx/fix-rsa-2048" {
		t.Fatalf("after CreateBranch the branch is %q, want qryx/fix-rsa-2048", now)
	}
}

func TestAddAndCommitLeaveTheTreeClean(t *testing.T) {
	dir := gitRepo(t)
	var g GitCLI

	write(t, dir, "a.txt", "one, remediated\n")
	if err := g.Add([]string{"a.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := g.Commit("fix: raise the key size"); err != nil {
		t.Fatal(err)
	}

	dirty, err := g.Dirty([]string{"a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if dirty {
		t.Fatal("the file is still modified after Add and Commit")
	}

	out, err := run("git", "log", "-1", "--pretty=%s")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out); got != "fix: raise the key size" {
		t.Fatalf("the commit subject is %q, want the message that was passed", got)
	}
}

// A failure has to name what failed and why. These commands run inside
// somebody else's automation, where the only thing anybody sees is the error
// string: "exit status 128" is not something a person can act on.
func TestAFailureNamesTheCommandAndCarriesGitsOwnComplaint(t *testing.T) {
	gitRepo(t)

	_, err := run("git", "rev-parse", "--abbrev-ref", "no-such-ref-anywhere")
	if err == nil {
		t.Fatal("resolving a ref that does not exist succeeded")
	}
	msg := err.Error()
	if !strings.Contains(msg, "git rev-parse") {
		t.Fatalf("the error does not name the command that failed: %q", msg)
	}
	// Asserted on a word only git says, never on the ref name. The first
	// version looked for "no-such-ref-anywhere", which is in the ARGS: with
	// the stderr dropped entirely the message still echoed the arguments and
	// the test stayed green. Found by dropping it and watching nothing happen.
	if !strings.Contains(msg, "unknown revision") {
		t.Fatalf("the error does not carry git's own complaint, so the reader "+
			"is left with a command line and an exit status: %q", msg)
	}
}

// A command that is not installed fails with the exec error rather than with
// an empty message, because there is no stderr to quote.
func TestAMissingBinaryStillProducesAReadableError(t *testing.T) {
	_, err := run("qryx-no-such-binary-anywhere", "--help")
	if err == nil {
		t.Fatal("running a binary that does not exist succeeded")
	}
	if !strings.Contains(err.Error(), "qryx-no-such-binary-anywhere") {
		t.Fatalf("the error does not name the missing binary: %q", err)
	}
}
