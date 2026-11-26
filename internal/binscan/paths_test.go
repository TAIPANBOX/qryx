package binscan

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A directory is walked for binaries: nested ones are found, text files are
// skipped, and a symlink is not followed, so one binary linked twice is one
// finding and a link cannot lead the walk out of the tree it was given.
func TestScanWalksADirectoryAndSkipsLinksAndText(t *testing.T) {
	root := t.TempDir()
	elfPath := buildStaticELF(t, "main", "RSA_new")
	raw, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "usr", "lib", "app")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("RSA_new appears in this text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(nested, filepath.Join(root, "app-link")); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Asset.Algorithm != "RSA" || findings[0].Location.File != nested {
		t.Fatalf("got %+v, want one RSA finding at %s", findings, nested)
	}

	// A file path and a directory together: each contributes.
	findings, err = Scan([]string{root, elfPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Errorf("a directory and a file gave %d findings, want 2", len(findings))
	}

	if _, err := Scan([]string{root, filepath.Join(root, "missing")}); err == nil {
		t.Error("a path that does not exist must be an error, not a skipped target")
	}
}

// buildDarwinBinary cross-compiles a pure-Go Mach-O, the same way the PE
// fixture is built, so the Mach-O path is exercised on every platform and not
// only on a Mac that happens to have system binaries to read.
func buildDarwinBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hi\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module machofixture\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fixture")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compiling the Mach-O fixture: %v\n%s", err, b)
	}
	return out
}

// wrapFat puts one thin Mach-O inside a universal (fat) container, the shape
// every system binary on a current Mac has.
func wrapFat(t *testing.T, thinPath string) string {
	t.Helper()
	thin, err := os.ReadFile(thinPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := macho.Open(thinPath)
	if err != nil {
		t.Fatal(err)
	}
	cpu, sub := uint32(f.Cpu), f.SubCpu
	f.Close()

	const offset = 1 << 14
	var buf bytes.Buffer
	for _, v := range []uint32{macho.MagicFat, 1, cpu, sub, offset, uint32(len(thin)), 14} {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	buf.Write(make([]byte, offset-buf.Len()))
	buf.Write(thin)
	p := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(p, buf.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A thin and a universal Mach-O both parse and yield the libraries they link.
// A Mach-O path that silently returned nothing would report every macOS binary
// in an estate as carrying no cryptography.
func TestMachOThinAndUniversalYieldTheirImports(t *testing.T) {
	thin := buildDarwinBinary(t)
	for name, path := range map[string]string{"thin": thin, "universal": wrapFat(t, thin)} {
		libs, syms, ok := imports(path)
		if !ok {
			t.Fatalf("%s: a real Mach-O did not parse", name)
		}
		if !strings.Contains(strings.Join(libs, " "), "libSystem") {
			t.Errorf("%s: libraries %v do not include libSystem", name, libs)
		}
		if len(syms) == 0 {
			t.Errorf("%s: no imported symbols read", name)
		}
	}

	// Mach-O magic on something that is not one is refused, not parsed as empty.
	fake := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(fake, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 9, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := imports(fake); ok {
		t.Error("a truncated file with fat magic was accepted as a Mach-O")
	}
}
