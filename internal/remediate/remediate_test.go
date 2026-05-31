package remediate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// writeScan writes src to a temp file and returns a scan.Result whose finding
// points at it, so Plan can read it back from disk.
func writeScan(t *testing.T, src string, f model.Finding) *scan.Result {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f.Location.File = "main.go"
	return &scan.Result{Root: dir, Findings: []model.Finding{f}}
}

func rsaFinding(bits int) model.Finding {
	return model.Finding{
		Asset:  model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: bits, Primitive: model.PrimitiveSignature},
		Source: "goast",
	}
}

const tmplRSA = `package x

import (
	"crypto/rand"
	"crypto/rsa"
)

func f() { _, _ = rsa.GenerateKey(rand.Reader, %s) }
`

func TestRaisesSubFloorRSA(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits int
		want bool
	}{
		{"1024 below floor", 1024, true},
		{"2048 below 3072 floor", 2048, true},
		{"3072 at floor", 3072, false},
		{"4096 above floor", 4096, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(tmplRSA, "%s", strconv.Itoa(tc.bits), 1)
			res := writeScan(t, src, rsaFinding(tc.bits))
			patches, err := Plan(res, 3072)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(patches) == 1; got != tc.want {
				t.Fatalf("patches=%d want patch=%v", len(patches), tc.want)
			}
			if !tc.want {
				return
			}
			if !strings.Contains(patches[0].NewContent, "rsa.GenerateKey(rand.Reader, 3072)") {
				t.Errorf("new content not raised to 3072:\n%s", patches[0].NewContent)
			}
			mustParse(t, patches[0].NewContent)
		})
	}
}

func TestNonLiteralSizeNotPatched(t *testing.T) {
	src := `package x

import (
	"crypto/rand"
	"crypto/rsa"
)

func f(keyLen int) { _, _ = rsa.GenerateKey(rand.Reader, keyLen) }
`
	res := writeScan(t, src, rsaFinding(1024))
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 0 {
		t.Fatalf("variable size must not be patched, got %d", len(patches))
	}
}

func TestNonRSAIgnored(t *testing.T) {
	src := `package x

import "crypto/md5"

func f() { _ = md5.New() }
`
	res := writeScan(t, src, model.Finding{
		Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5", Primitive: model.PrimitiveHash},
		Location: model.Location{File: "main.go"},
		Source:   "goast",
	})
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 0 {
		t.Fatalf("MD5 has no safe auto-fix, got %d", len(patches))
	}
}

func TestTwoKeysOneFile(t *testing.T) {
	src := `package x

import (
	"crypto/rand"
	"crypto/rsa"
)

func a() { _, _ = rsa.GenerateKey(rand.Reader, 1024) }
func b() { _, _ = rsa.GenerateKey(rand.Reader, 2048) }
`
	res := writeScan(t, src, rsaFinding(1024))
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 1 {
		t.Fatalf("want one patch for the file, got %d", len(patches))
	}
	got := strings.Count(patches[0].NewContent, "rsa.GenerateKey(rand.Reader, 3072)")
	if got != 2 {
		t.Errorf("both keys should be raised, got %d", got)
	}
	if strings.Count(patches[0].Diff, "@@") != 2 {
		t.Errorf("expected two hunks in diff:\n%s", patches[0].Diff)
	}
}

func TestDiffFormat(t *testing.T) {
	src := strings.Replace(tmplRSA, "%s", "1024", 1)
	res := writeScan(t, src, rsaFinding(1024))
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	d := patches[0].Diff
	for _, want := range []string{"--- a/main.go", "+++ b/main.go", "@@ -", "-func f() { _, _ = rsa.GenerateKey(rand.Reader, 1024) }", "+func f() { _, _ = rsa.GenerateKey(rand.Reader, 3072) }"} {
		if !strings.Contains(d, want) {
			t.Errorf("diff missing %q:\n%s", want, d)
		}
	}
}

func TestMinBitsHonored(t *testing.T) {
	src := strings.Replace(tmplRSA, "%s", "2048", 1)
	res := writeScan(t, src, rsaFinding(2048))
	patches, err := Plan(res, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 1 || !strings.Contains(patches[0].NewContent, "4096") {
		t.Fatalf("expected raise to 4096, got %+v", patches)
	}
}

func tfRSAFinding(bits int) model.Finding {
	return model.Finding{
		Asset:  model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: bits, Primitive: model.PrimitiveSignature},
		Source: "terraform",
	}
}

func writeScanTF(t *testing.T, src string, f model.Finding) *scan.Result {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f.Location.File = "main.tf"
	return &scan.Result{Root: dir, Findings: []model.Finding{f}}
}

func TestTerraformRSABitsRaised(t *testing.T) {
	src := "resource \"tls_private_key\" \"k\" {\n  algorithm = \"RSA\"\n  rsa_bits  = 1024\n}\n"
	res := writeScanTF(t, src, tfRSAFinding(1024))
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	if !strings.Contains(patches[0].NewContent, "rsa_bits  = 3072") {
		t.Errorf("rsa_bits not raised:\n%s", patches[0].NewContent)
	}
	if patches[0].Rule != "tf-rsa-bits" {
		t.Errorf("rule=%q", patches[0].Rule)
	}
}

func TestTerraformRSABitsAtFloorNoOp(t *testing.T) {
	src := "resource \"tls_private_key\" \"k\" {\n  rsa_bits = 4096\n}\n"
	res := writeScanTF(t, src, tfRSAFinding(4096))
	patches, err := Plan(res, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 0 {
		t.Fatalf("4096 >= floor must not be patched, got %d", len(patches))
	}
}

func mustParse(t *testing.T, src string) {
	t.Helper()
	if _, err := parser.ParseFile(token.NewFileSet(), "", src, 0); err != nil {
		t.Fatalf("rewritten source does not parse: %v", err)
	}
}
