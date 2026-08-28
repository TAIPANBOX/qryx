// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by RUNNING rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, and building twenty-two
// repositories in its CI is a matrix it does not have. This repository already
// runs its suite on every push, so the marginal cost of a few process starts is
// seconds.
//
// What is proved here is exactly the `checked` bucket and nothing else. The
// `declared` bucket is not asserted against anything, on purpose: a test that
// pretended to verify a sentence about purpose would be the failure this whole
// design exists to avoid.
package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type component struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Checked struct {
		Package                             string            `json:"package"`
		Subcommand                          string            `json:"subcommand"`
		Env                                 map[string]string `json:"env"`
		ReadsNoEnvironment                  bool              `json:"reads_no_environment"`
		CompletedExitCode                   int               `json:"completed_exit_code"`
		ToolErrorExitCode                   int               `json:"tool_error_exit_code"`
		FindingsWhenAskedExitCode           int               `json:"findings_when_asked_exit_code"`
		FindingsAloneDoNotChangeTheExitCode bool              `json:"findings_alone_do_not_change_the_exit_code"`
	} `json:"checked"`
}

type manifest struct {
	Schema     string      `json:"schema"`
	Repo       string      `json:"repo"`
	Components []component `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	b, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("reading components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing components.json: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares no component, so every test here measured nothing")
	}
	return m, r
}

func tool(t *testing.T, m manifest) component {
	t.Helper()
	for _, c := range m.Components {
		if c.Class == "tool" {
			return c
		}
	}
	t.Fatal("components.json declares no tool, so the running half measured nothing")
	return component{}
}

func build(t *testing.T, r, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "qryx")
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = r
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func status(t *testing.T, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("running %v: %v", args, err)
	return -1, ""
}

// THE ONE THAT CLOSES THE HOLE. A binary this repository builds and does not
// declare is invisible from outside by construction, which is what estate-gates
// invariant 18 says about its own `runs` field.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	list := exec.Command("go", "list", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./...")
	// Without this the command runs in THIS package's directory and `./...`
	// means this package alone. It then finds no main package, and the test
	// passes while measuring nothing.
	list.Dir = r
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package in this repository, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it.\n"+
				"A component nobody declares is one no deployment can be asked to install.", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// A declared subcommand is one the binary actually dispatches on.
func TestEveryDeclaredSubcommandIsOneTheBinaryDispatchesOn(t *testing.T) {
	m, r := load(t)

	b, err := os.ReadFile(filepath.Join(r, "cmd", "qryx", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	known := map[string]bool{}
	for _, hit := range regexp.MustCompile(`(?m)^\tcase "([a-z-]+)":`).FindAllStringSubmatch(string(b), -1) {
		known[hit[1]] = true
	}
	if len(known) == 0 {
		t.Fatal("main.go no longer dispatches with a top-level `case \"...\":`, so this measured nothing")
	}
	checked := 0
	for _, c := range m.Components {
		if c.Checked.Subcommand == "" {
			continue
		}
		checked++
		if !known[c.Checked.Subcommand] {
			t.Errorf("components.json says %s runs `qryx %s` and main.go dispatches no such subcommand",
				c.Name, c.Checked.Subcommand)
		}
	}
	if checked == 0 {
		t.Fatal("no component declares a subcommand, so this measured nothing")
	}
}

// THE INVERTED ONE.
//
// Every other manifest in this estate lists environment variables, and its test
// fails when it finds none, on the grounds that finding none means the reader
// broke. Here finding none is the truth: there is no QRYX_ name anywhere in this
// repository, test files included. So the claim is `reads_no_environment` and
// what is checked is that the set really is EMPTY. The day somebody adds one,
// this goes red and the manifest has to grow an entry.
//
// The regex is the one every sibling uses, so this also proves the reader
// itself works: it is run against a name planted in a temporary file, and must
// find that.
func TestItReadsNoEnvironmentAtAllAndTheReaderStillWorks(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`QRYX_[A-Z0-9_]+`)

	// The reader, proved against a subject that is not this repository. Without
	// this, "found nothing" and "cannot find anything" are the same result.
	planted := filepath.Join(t.TempDir(), "planted.go")
	if err := os.WriteFile(planted, []byte("package x\n\nconst n = \"QRYX_PLANTED\"\n"), 0o600); err != nil {
		t.Fatalf("planting: %v", err)
	}
	b, err := os.ReadFile(planted)
	if err != nil {
		t.Fatalf("reading the planted file: %v", err)
	}
	if got := name.FindAllString(string(b), -1); len(got) != 1 {
		t.Fatalf("the reader found %v in a file containing exactly one name, so a "+
			"finding of none below would prove nothing", got)
	}

	var found []string
	err = filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			// This package and no other. The prover above needs a QRYX_ name in
			// its own source to show the reader can find one, and without this
			// the test finds that and reports itself. The claim is therefore
			// "no QRYX_ name anywhere except in the file that proves the reader
			// works", which is stronger than the siblings' "none in non-test
			// source" and is the strongest form that can be self-consistent.
			if path == filepath.Join(r, "internal", "manifest") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range name.FindAllString(string(src), -1) {
			found = append(found, n+" in "+strings.TrimPrefix(path, r+"/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	sort.Strings(found)

	c := tool(t, m)
	if c.Checked.ReadsNoEnvironment {
		for _, f := range found {
			t.Errorf("components.json says this repository reads no environment variable, "+
				"and here is one: %s", f)
		}
		if len(c.Checked.Env) != 0 {
			t.Errorf("components.json claims reads_no_environment and also declares %d "+
				"variable(s). Those cannot both be true.", len(c.Checked.Env))
		}
		return
	}
	if len(found) == 0 {
		t.Fatal("no QRYX_ name found and the manifest does not claim there are none, " +
			"so either the reader broke or the manifest is behind")
	}
}

// AND THE HALF NO CENTRAL FILE COULD EVER DO: the exit codes, which mean the
// OPPOSITE of mockryx's in the same estate.
//
// The one worth proving is that findings alone do not move the code. A scan of a
// file with real findings exits 0 unless a flag asked otherwise, so a caller
// reading 0 as "nothing found" would be wrong every time.
func TestFindingsAloneDoNotChangeTheExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	m, r := load(t)
	c := tool(t, m)
	bin := build(t, r, c.Checked.Package)
	sub := c.Checked.Subcommand

	// A file with two findings a crypto scanner must see: MD5 and RSA-1024.
	dir := t.TempDir()
	src := "package weak\n\nimport (\n\t\"crypto/md5\"\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\n" +
		"func Hash(b []byte) []byte { h := md5.Sum(b); return h[:] }\n" +
		"func Key() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 1024) }\n"
	if err := os.WriteFile(filepath.Join(dir, "weak.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing the subject: %v", err)
	}

	got, out := status(t, bin, sub, dir)
	// The fixture has to actually produce findings, or the whole test is about
	// a clean scan and proves nothing about findings at all.
	if !strings.Contains(out, "MD5") {
		t.Fatalf("the scan found no MD5 in a file that uses it, so this measured nothing:\n%s", out)
	}
	if want := c.Checked.CompletedExitCode; got != want {
		t.Errorf("a completed scan WITH findings exited %d; components.json says %d.\n"+
			"That is the claim: findings alone do not change the code.\n%s", got, want, out)
	}

	if want := c.Checked.FindingsWhenAskedExitCode; want != 0 {
		if got, out := status(t, bin, sub, "--fail-on", "high", dir); got != want {
			t.Errorf("`--fail-on high` over the same findings exited %d; components.json says %d\n%s",
				got, want, out)
		}
	}

	if want := c.Checked.ToolErrorExitCode; want != 0 {
		if got, _ := status(t, bin, sub, filepath.Join(dir, "no-such-path")); got != want {
			t.Errorf("scanning a path that does not exist exited %d; components.json says %d", got, want)
		}
		if got, _ := status(t, bin, sub); got != want {
			t.Errorf("scanning with no path at all exited %d; components.json says %d", got, want)
		}
	}
}
