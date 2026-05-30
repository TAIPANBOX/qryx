package binscan

import (
	"debug/elf"
	"os"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func TestCryptoFromSymbols(t *testing.T) {
	syms := []string{
		"MD5_Init", "MD5_Update", // one MD5 finding, not two
		"SHA1_Final",
		"SHA256_Init",
		"RSA_new",
		"ECDSA_do_sign",
		"DES_set_key",
		"RC4",
		"DH_generate_key",
		"printf", "malloc", "memcpy", // unrelated: must not match
	}
	got := cryptoFromSymbols("bin", syms)

	want := map[string]bool{"MD5": true, "SHA-1": true, "SHA-256": true, "RSA": true, "ECDSA": true, "DES": true, "RC4": true, "DH": true}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), algos(got))
	}
	for _, f := range got {
		if !want[f.Asset.Algorithm] {
			t.Errorf("unexpected algorithm %q", f.Asset.Algorithm)
		}
	}
}

func TestCryptoFromSymbolsNoFalsePositives(t *testing.T) {
	if got := cryptoFromSymbols("bin", []string{"printf", "strlen", "main", "abort"}); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", algos(got))
	}
}

func TestIsELFRejectsNonELF(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("not an elf")
	f.Close()
	if isELF(f.Name()) {
		t.Error("plain text reported as ELF")
	}
}

// TestScanRealELF parses a real libcrypto-linked binary when one is available
// (Linux CI). It skips where no ELF is found (e.g. macOS, where this dev env
// runs and system binaries are Mach-O).
func TestScanRealELF(t *testing.T) {
	candidates := []string{"/usr/bin/openssl", "/bin/openssl", "/usr/bin/curl", "/usr/bin/ssh"}
	var target string
	for _, c := range candidates {
		if _, err := elf.Open(c); err == nil {
			target = c
			break
		}
	}
	if target == "" {
		t.Skip("no ELF binary with crypto available; skipping (non-Linux env)")
	}

	findings, err := Scan([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected crypto findings from %s", target)
	}
	for _, f := range findings {
		if f.Location.File != target || f.Source != "elf" {
			t.Errorf("bad finding metadata: %+v", f)
		}
	}
}

func algos(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Asset.Algorithm
	}
	return out
}
