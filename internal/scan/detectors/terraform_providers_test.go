package detectors

import (
	"testing"
)

// Azure Key Vault keys: the key type decides the algorithm, an explicit
// key_size is read and its absence means the provider's 2048, and a key type
// qryx does not know, or one set from a variable, produces no finding rather
// than a guessed one.
func TestTerraformAzureKeyTypes(t *testing.T) {
	for _, tc := range []struct {
		src       string
		algo      string
		size      int
		wantFound bool
	}{
		{`key_type = "RSA-HSM"
  key_size = 4096`, "RSA", 4096, true},
		{`key_type = "RSA"`, "RSA", 2048, true},
		{`key_type = "EC-HSM"`, "ECDSA", 0, true},
		{`key_type = "oct"`, "AES", 0, true},
		{`key_type = "oct-HSM"`, "AES", 0, true},
		{`key_type = "quantum"`, "", 0, false},
		{`key_type = var.kt`, "", 0, false},
	} {
		got := detectTF(t, "resource \"azurerm_key_vault_key\" \"k\" {\n  "+tc.src+"\n}")
		if !tc.wantFound {
			if len(got) != 0 {
				t.Errorf("%s: want no finding, got %+v", tc.src, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Asset.Algorithm != tc.algo || got[0].Asset.KeySize != tc.size {
			t.Errorf("%s: got %+v, want %s-%d", tc.src, got, tc.algo, tc.size)
			continue
		}
		if got[0].Location.Line != 2 {
			t.Errorf("%s: line %d, want the key_type line 2", tc.src, got[0].Location.Line)
		}
	}
}

// Google KMS keys carry the algorithm in a nested version_template block. Each
// family maps to its asset with the RSA size read out of the enum name; a key
// with no template, an algorithm from a variable, or one qryx does not track
// produces no finding.
func TestTerraformGoogleKMSAlgorithms(t *testing.T) {
	block := func(inner string) string {
		return "resource \"google_kms_crypto_key\" \"k\" {\n  name = \"k\"\n" + inner + "}"
	}
	tmpl := func(alg string) string {
		return block("  version_template {\n    algorithm = " + alg + "\n  }\n")
	}
	for _, tc := range []struct {
		alg  string
		algo string
		size int
	}{
		{`"RSA_SIGN_PSS_3072_SHA256"`, "RSA", 3072},
		{`"RSA_DECRYPT_OAEP_2048_SHA256"`, "RSA", 2048},
		{`"EC_SIGN_P256_SHA256"`, "ECDSA", 0},
		{`"HMAC_SHA256"`, "HMAC", 0},
		{`"GOOGLE_SYMMETRIC_ENCRYPTION"`, "AES", 256},
	} {
		got := detectTF(t, tmpl(tc.alg))
		if len(got) != 1 || got[0].Asset.Algorithm != tc.algo || got[0].Asset.KeySize != tc.size {
			t.Errorf("%s: got %+v, want %s-%d", tc.alg, got, tc.algo, tc.size)
			continue
		}
		if got[0].Location.Line != 4 {
			t.Errorf("%s: line %d, want the algorithm line 4", tc.alg, got[0].Location.Line)
		}
	}
	for _, src := range []string{
		tmpl(`"PQ_SIGN_UNKNOWN"`),
		tmpl(`var.alg`),
		block("  labels = {}\n  rotation {\n  }\n"),
	} {
		if got := detectTF(t, src); len(got) != 0 {
			t.Errorf("want no finding for\n%s\ngot %+v", src, got)
		}
	}
}

// An AWS KMS key whose spec is not a literal is still a key, read as the
// provider's default, and placed on the resource line.
func TestTerraformAWSKMSKeyWithAComputedSpec(t *testing.T) {
	got := detectTF(t, "resource \"aws_kms_key\" \"k\" {\n  customer_master_key_spec = var.spec\n}")
	if len(got) != 1 || got[0].Asset.Algorithm != "AES" || got[0].Location.Line != 1 {
		t.Errorf("got %+v, want the default AES key on line 1", got)
	}
}
