package binscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Windows half of the scanner, which had no test at all.
//
// A binary format this scanner cannot parse does not error: it yields nothing,
// and nothing is what a clean binary yields too. So a broken PE path would
// report every Windows executable in an estate as carrying no cryptography,
// and the report would look exactly like good news.
//
// The fixture is built here rather than committed. A 2 MB binary in a
// repository is worse than a `go build`, and Go cross-compiles a PE with no
// toolchain beyond itself and no cgo.

func buildWindowsBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hi\") }\n"), 0o600); err != nil {
		t.Fatalf("write fixture source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module pefixture\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}
	out := filepath.Join(dir, "fixture.exe")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		// Not a skip. Cross-compiling a pure-Go binary needs nothing this
		// machine does not already have to run `go test`, so a failure here is
		// a real problem and reporting it as "not exercised" would hide it.
		t.Fatalf("cross-compiling the PE fixture: %v\n%s", err, b)
	}
	return out
}

func TestAWindowsBinaryYieldsItsImportsRatherThanSilentlyNothing(t *testing.T) {
	t.Parallel()

	bin := buildWindowsBinary(t)
	libs, syms, ok := imports(bin)
	if !ok {
		t.Fatal("a real PE must parse; ok=false here means every Windows binary in " +
			"an estate is reported as carrying no cryptography")
	}

	// The asymmetry worth knowing before changing any of this. A pure-Go
	// Windows binary reports ZERO imported libraries and dozens of imported
	// SYMBOLS, each qualified with the DLL it comes from. A scanner that read
	// only `libs` would find nothing in this whole class of binary and the
	// report would look like good news.
	if len(syms) == 0 {
		t.Fatalf("no imported symbols read from a PE that has them; libs=%v", libs)
	}
	joined := strings.Join(syms, " ")
	if !strings.Contains(strings.ToLower(joined), "kernel32") {
		t.Errorf("the symbols read do not name the DLL they come from: %v", syms[:min(5, len(syms))])
	}
}

func TestSomethingThatIsNotABinaryIsRefusedRatherThanReportedClean(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"plain text", []byte("this is not a binary at all\n")},
		{"empty", []byte{}},
		{"MZ header and nothing behind it", []byte("MZ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.WriteFile(p, tc.content, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, ok := imports(p); ok {
				t.Error("a file that is not a parseable binary must report ok=false, " +
					"so the caller can tell 'not scanned' from 'scanned and clean'")
			}
		})
	}

	if _, _, ok := imports(filepath.Join(dir, "does-not-exist")); ok {
		t.Error("a missing file must report ok=false")
	}
}

func TestTheFormatIsChosenByMagicBytesAndNotByExtension(t *testing.T) {
	t.Parallel()

	// A scanner walking somebody else's filesystem meets binaries named
	// anything at all. Dispatching on the extension would miss every one of
	// them, silently.
	bin := buildWindowsBinary(t)
	renamed := filepath.Join(t.TempDir(), "no-extension-at-all")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(renamed, b, 0o600); err != nil {
		t.Fatalf("write renamed fixture: %v", err)
	}

	if _, syms, ok := imports(renamed); !ok || len(syms) == 0 {
		t.Error("a PE named without an extension must still parse: the format comes " +
			"from the magic bytes, not the name")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
