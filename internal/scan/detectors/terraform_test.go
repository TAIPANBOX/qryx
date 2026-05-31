package detectors

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func detectTF(t *testing.T, src string) []model.Finding {
	t.Helper()
	return NewTerraform().Detect(scan.File{Path: "main.tf", Content: []byte(src)})
}

func TestTerraformTLSPrivateKey(t *testing.T) {
	got := detectTF(t, `resource "tls_private_key" "k" {
  algorithm = "RSA"
  rsa_bits  = 1024
}`)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Asset.Algorithm != "RSA" || got[0].Asset.KeySize != 1024 {
		t.Errorf("got %+v, want RSA-1024", got[0].Asset)
	}
	if got[0].Source != "terraform" {
		t.Errorf("source=%q", got[0].Source)
	}
}

func TestTerraformDefaults(t *testing.T) {
	// No rsa_bits => TF default 2048; no algorithm => default RSA.
	got := detectTF(t, `resource "tls_private_key" "k" {}`)
	if len(got) != 1 || got[0].Asset.Algorithm != "RSA" || got[0].Asset.KeySize != 2048 {
		t.Fatalf("want RSA-2048 default, got %+v", got)
	}
}

func TestTerraformECDSA(t *testing.T) {
	got := detectTF(t, `resource "tls_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}`)
	if len(got) != 1 || got[0].Asset.Algorithm != "ECDSA" {
		t.Fatalf("want ECDSA, got %+v", got)
	}
}

func TestTerraformKMSSpecs(t *testing.T) {
	tests := []struct {
		spec     string
		wantAlgo string
		wantSize int
	}{
		{"RSA_3072", "RSA", 3072},
		{"ECC_NIST_P256", "ECDSA", 0},
		{"HMAC_256", "HMAC", 0},
		{"SYMMETRIC_DEFAULT", "AES", 256},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			got := detectTF(t, `resource "aws_kms_key" "k" {
  customer_master_key_spec = "`+tc.spec+`"
}`)
			if len(got) != 1 {
				t.Fatalf("want 1, got %d", len(got))
			}
			if got[0].Asset.Algorithm != tc.wantAlgo || got[0].Asset.KeySize != tc.wantSize {
				t.Errorf("got %+v, want %s/%d", got[0].Asset, tc.wantAlgo, tc.wantSize)
			}
		})
	}
}

func TestTerraformKMSDefaultSymmetric(t *testing.T) {
	// No spec attribute => symmetric AES-256, classified as safe.
	got := detectTF(t, `resource "aws_kms_key" "k" {
  description = "default"
}`)
	if len(got) != 1 || got[0].Asset.Algorithm != "AES" {
		t.Fatalf("want AES default, got %+v", got)
	}
}

func TestTerraformAzureKey(t *testing.T) {
	got := detectTF(t, `resource "azurerm_key_vault_key" "k" {
  key_type = "RSA"
  key_size = 4096
}`)
	if len(got) != 1 || got[0].Asset.Algorithm != "RSA" || got[0].Asset.KeySize != 4096 {
		t.Fatalf("want RSA-4096, got %+v", got)
	}
}

func TestTerraformOneAssetPerResource(t *testing.T) {
	// algorithm and rsa_bits in the same block must yield exactly one asset.
	got := detectTF(t, `resource "tls_private_key" "k" {
  algorithm = "RSA"
  rsa_bits  = 2048
}`)
	if len(got) != 1 {
		t.Fatalf("want 1 asset, got %d (double count?)", len(got))
	}
}

func TestTerraformIgnoresCommentsAndStrings(t *testing.T) {
	// A brace inside a string/comment must not confuse the parser, and a
	// non-crypto resource must be ignored.
	got := detectTF(t, `resource "aws_s3_bucket" "b" {
  tags = { name = "has } brace" } # trailing } comment
}

resource "tls_private_key" "k" {
  algorithm = "RSA"
  rsa_bits  = 1024
}`)
	if len(got) != 1 || got[0].Asset.KeySize != 1024 {
		t.Fatalf("brace/comment handling failed, got %+v", got)
	}
}

func TestTerraformHeredocNotMatched(t *testing.T) {
	// "rsa_bits = 512" appears only inside a heredoc string; the HCL parser
	// must not treat it as an attribute (a regex scanner would mis-match).
	got := detectTF(t, `resource "local_file" "doc" {
  content = <<-EOT
    example config:
    rsa_bits = 512
  EOT
}`)
	if len(got) != 0 {
		t.Fatalf("heredoc text must not produce a finding, got %+v", got)
	}
}

func TestTerraformInterpolatedSizeUnknown(t *testing.T) {
	// rsa_bits bound to a variable cannot be statically resolved: detect RSA
	// but with unknown size (0), never a guessed value.
	got := detectTF(t, `variable "bits" { default = 1024 }
resource "tls_private_key" "k" {
  algorithm = "RSA"
  rsa_bits  = var.bits
}`)
	if len(got) != 1 || got[0].Asset.Algorithm != "RSA" || got[0].Asset.KeySize != 0 {
		t.Fatalf("interpolated size should be RSA/0, got %+v", got)
	}
}

func TestTerraformGoogleKMS(t *testing.T) {
	tests := []struct {
		alg      string
		wantAlgo string
		wantSize int
	}{
		{"RSA_SIGN_PKCS1_2048_SHA256", "RSA", 2048},
		{"RSA_DECRYPT_OAEP_3072_SHA256", "RSA", 3072},
		{"EC_SIGN_P256_SHA256", "ECDSA", 0},
		{"GOOGLE_SYMMETRIC_ENCRYPTION", "AES", 256},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			got := detectTF(t, `resource "google_kms_crypto_key" "k" {
  name = "k"
  version_template {
    algorithm = "`+tc.alg+`"
  }
}`)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d", len(got))
			}
			if got[0].Asset.Algorithm != tc.wantAlgo || got[0].Asset.KeySize != tc.wantSize {
				t.Errorf("got %+v, want %s/%d", got[0].Asset, tc.wantAlgo, tc.wantSize)
			}
		})
	}
}
