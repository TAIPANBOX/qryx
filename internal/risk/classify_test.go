package risk

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		asset   model.Asset
		wantC   model.RiskClass
		wantSev model.Severity
	}{
		{"rsa 2048 quantum", model.Asset{Algorithm: "RSA", KeySize: 2048}, model.RiskQuantumVulnerable, model.SeverityHigh},
		{"rsa 1024 weak", model.Asset{Algorithm: "RSA", KeySize: 1024}, model.RiskWeak, model.SeverityCritical},
		{"md5 weak", model.Asset{Algorithm: "MD5"}, model.RiskWeak, model.SeverityHigh},
		{"sha1 weak", model.Asset{Algorithm: "SHA-1"}, model.RiskWeak, model.SeverityHigh},
		{"sha256 ok", model.Asset{Algorithm: "SHA-256"}, model.RiskNone, model.SeverityNone},
		{"aes ok", model.Asset{Algorithm: "AES"}, model.RiskNone, model.SeverityNone},
		{"ecdsa quantum", model.Asset{Algorithm: "ECDSA"}, model.RiskQuantumVulnerable, model.SeverityHigh},
		{"ml-kem ok", model.Asset{Algorithm: "ML-KEM"}, model.RiskNone, model.SeverityNone},
		{"unknown none", model.Asset{Algorithm: "FROBNICATE"}, model.RiskNone, model.SeverityNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.asset)
			if got.Class != tt.wantC {
				t.Errorf("class = %q, want %q", got.Class, tt.wantC)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("severity = %v, want %v", got.Severity, tt.wantSev)
			}
		})
	}
}

func TestNormalizeAlgorithm(t *testing.T) {
	cases := map[string]string{
		"sha1":       "SHA-1",
		"SHA256":     "SHA-256",
		"tripledes":  "3DES",
		"ecdsa-p256": "ECDSA",
		"ml-kem-768": "ML-KEM",
		"sha3-256":   "SHA3",
	}
	for in, want := range cases {
		if got := NormalizeAlgorithm(in); got != want {
			t.Errorf("NormalizeAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}
