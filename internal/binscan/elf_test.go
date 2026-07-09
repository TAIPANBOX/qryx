package binscan

import (
	"debug/elf"
	"debug/macho"
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

// TestCryptoFromSymbolsEVP pins the OpenSSL 3.x EVP_* detection rules against
// the real dynamic symbol set imported by /usr/bin/openssl on Ubuntu (nm -D),
// which is almost entirely EVP_* — the legacy flat API (RSA_new, MD5_Init,
// ...) barely appears anymore. Before this test, none of these symbols
// matched any rule and a scan of a modern openssl binary found near nothing.
func TestCryptoFromSymbolsEVP(t *testing.T) {
	tests := []struct {
		sym  string
		algo string
		prim model.Primitive
	}{
		{"EVP_aes_256_cbc", "AES", model.PrimitiveEncryption},
		{"EVP_aes_128_gcm", "AES", model.PrimitiveEncryption},
		{"AES_encrypt", "AES", model.PrimitiveEncryption},
		{"AES_set_encrypt_key", "AES", model.PrimitiveEncryption},
		{"EVP_des_ede3_cbc", "3DES", model.PrimitiveEncryption},
		{"EVP_md5", "MD5", model.PrimitiveHash},
		{"EVP_sha1", "SHA-1", model.PrimitiveHash},
		{"EVP_sha256", "SHA-256", model.PrimitiveHash},
		{"EVP_sha512", "SHA-512", model.PrimitiveHash},
		{"EVP_PKEY_CTX_set_rsa_keygen_bits", "RSA", model.PrimitiveSignature},
		{"EVP_PKEY_CTX_set1_rsa_keygen_pubexp", "RSA", model.PrimitiveSignature},
		{"EVP_PKEY_get0_RSA", "RSA", model.PrimitiveSignature},
		{"EVP_PKEY_CTX_set_ec_paramgen_curve_nid", "ECDSA", model.PrimitiveSignature},
		{"EVP_PKEY_CTX_set_dsa_paramgen_bits", "DSA", model.PrimitiveSignature},
		{"EVP_PKEY_CTX_set_dh_paramgen_prime_len", "DH", model.PrimitiveKeyExch},
		{"EVP_PKEY_CTX_set_dh_nid", "DH", model.PrimitiveKeyExch},
		// Generic entry points with no statically-resolvable algorithm: still
		// reported (an EVP-flavored crypto library is clearly in use) rather
		// than silently dropped, per the bug report ("EVP_EncryptInit/
		// EVP_DecryptInit -> symmetric; EVP_DigestInit + EVP_MD_* -> hashing;
		// EVP_PKEY_* -> asymmetric").
		{"EVP_EncryptInit_ex", "EVP_CIPHER", model.PrimitiveEncryption},
		{"EVP_DecryptInit_ex", "EVP_CIPHER", model.PrimitiveEncryption},
		{"EVP_DigestInit_ex", "EVP_MD", model.PrimitiveHash},
		{"EVP_MD_CTX_new", "EVP_MD", model.PrimitiveHash},
		{"EVP_PKEY_sign", "EVP_PKEY", model.PrimitiveUnknown},
		{"EVP_PKEY_new", "EVP_PKEY", model.PrimitiveUnknown},
	}
	for _, tt := range tests {
		got := cryptoFromSymbols("bin", []string{tt.sym})
		if len(got) != 1 {
			t.Fatalf("%s: got %d findings, want 1: %+v", tt.sym, len(got), got)
		}
		if got[0].Asset.Algorithm != tt.algo {
			t.Errorf("%s: algorithm = %q, want %q", tt.sym, got[0].Asset.Algorithm, tt.algo)
		}
		if got[0].Asset.Primitive != tt.prim {
			t.Errorf("%s: primitive = %q, want %q", tt.sym, got[0].Asset.Primitive, tt.prim)
		}
	}
}

// TestCryptoFromSymbolsEVPDedup mirrors a real /usr/bin/openssl symbol table:
// many EVP_PKEY_* helpers alongside a handful of algorithm-specific ones. The
// specific algorithm must win over the generic catch-all, and each algorithm
// is still reported once.
func TestCryptoFromSymbolsEVPDedup(t *testing.T) {
	syms := []string{
		"EVP_PKEY_new", "EVP_PKEY_free", "EVP_PKEY_sign", "EVP_PKEY_verify",
		"EVP_PKEY_CTX_set_rsa_keygen_bits", "EVP_PKEY_CTX_set1_rsa_keygen_pubexp",
		"EVP_aes_256_cbc", "EVP_sha256", "EVP_md5",
	}
	got := cryptoFromSymbols("bin", syms)
	want := map[string]bool{"RSA": true, "AES": true, "SHA-256": true, "MD5": true, "EVP_PKEY": true}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), algos(got))
	}
	for _, f := range got {
		if !want[f.Asset.Algorithm] {
			t.Errorf("unexpected algorithm %q", f.Asset.Algorithm)
		}
	}
}

func TestCryptoLibsIncludesLibgcrypt(t *testing.T) {
	found := false
	for _, cl := range cryptoLibs {
		if cl.name == "libgcrypt" {
			found = true
		}
	}
	if !found {
		t.Fatal("libgcrypt not in cryptoLibs")
	}
	got := librariesToFindings("bin", []string{"libgcrypt.so.20"})
	if len(got) != 1 || got[0].Asset.Algorithm != "libgcrypt" {
		t.Fatalf("librariesToFindings(libgcrypt.so.20) = %+v, want one libgcrypt finding", got)
	}
}

func TestCryptoFromSymbolsNoFalsePositives(t *testing.T) {
	if got := cryptoFromSymbols("bin", []string{"printf", "strlen", "main", "abort", "_main"}); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", algos(got))
	}
}

func TestCryptoFromSymbolsStripsMachOUnderscore(t *testing.T) {
	got := cryptoFromSymbols("bin", []string{"_RSA_new", "_MD5_Init"})
	want := map[string]bool{"RSA": true, "MD5": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want RSA+MD5", algos(got))
	}
	for _, f := range got {
		if !want[f.Asset.Algorithm] {
			t.Errorf("unexpected %q", f.Asset.Algorithm)
		}
	}
}

func TestImportsRejectsNonBinary(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("not a binary")
	f.Close()
	if _, _, ok := imports(f.Name()); ok {
		t.Error("plain text reported as a binary")
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
		if f.Location.File != target || f.Source != "binary" {
			t.Errorf("bad finding metadata: %+v", f)
		}
	}
}

// TestScanRealMachO parses a real Mach-O system binary when available (macOS).
// Skips elsewhere (e.g. Linux CI).
func TestScanRealMachO(t *testing.T) {
	candidates := []string{"/usr/bin/openssl", "/usr/bin/ssh", "/usr/bin/curl", "/bin/cat"}
	var target string
	for _, c := range candidates {
		if f, err := macho.Open(c); err == nil {
			f.Close()
			target = c
			break
		}
		if f, err := macho.OpenFat(c); err == nil {
			f.Close()
			target = c
			break
		}
	}
	if target == "" {
		t.Skip("no Mach-O binary available; skipping (non-macOS env)")
	}

	findings, err := Scan([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Location.File != target || f.Source != "binary" {
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
