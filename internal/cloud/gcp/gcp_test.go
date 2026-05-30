package gcp

import (
	"context"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

type fakeLister struct{ versions []keyVersion }

func (f fakeLister) list(_ context.Context, _, _ string) ([]keyVersion, error) {
	return f.versions, nil
}

func TestScanWithMapsAlgorithms(t *testing.T) {
	l := fakeLister{versions: []keyVersion{
		{Name: "projects/p/.../v1", Algorithm: "RSA_SIGN_PKCS1_2048_SHA256"},
		{Name: "projects/p/.../v2", Algorithm: "EC_SIGN_P256_SHA256"},
		{Name: "projects/p/.../v3", Algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION"},
		{Name: "projects/p/.../v4", Algorithm: "PQ_SIGN_ML_DSA_65"},
		{Name: "projects/p/.../v5", Algorithm: "CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED"}, // dropped
	}}

	got, err := scanWith(context.Background(), l, "p", "global")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4 (UNSPECIFIED dropped)", len(got))
	}

	byAlgo := map[string]model.Asset{}
	for _, f := range got {
		byAlgo[f.Asset.Algorithm] = f.Asset
		if f.Source != "gcp-kms" || f.Location.File == "" {
			t.Errorf("bad metadata: %+v", f)
		}
	}
	if a, ok := byAlgo["RSA"]; !ok || a.KeySize != 2048 {
		t.Errorf("RSA size mismapped: %+v", a)
	}
	if _, ok := byAlgo["ECDSA"]; !ok {
		t.Error("EC_SIGN not mapped to ECDSA")
	}
	if a, ok := byAlgo["AES"]; !ok || a.KeySize != 256 {
		t.Errorf("symmetric not mapped to AES-256: %+v", a)
	}
	if _, ok := byAlgo["ML-DSA"]; !ok {
		t.Error("ML_DSA not mapped to ML-DSA")
	}
}

func TestAlgoToAsset(t *testing.T) {
	tests := []struct {
		algo string
		want string
		ok   bool
		size int
	}{
		{"RSA_DECRYPT_OAEP_4096_SHA256", "RSA", true, 4096},
		{"RSA_SIGN_PSS_3072_SHA256", "RSA", true, 3072},
		{"EC_SIGN_SECP256K1_SHA256", "ECDSA", true, 0},
		{"HMAC_SHA256", "HMAC", true, 0},
		{"GOOGLE_SYMMETRIC_ENCRYPTION", "AES", true, 256},
		{"PQ_SIGN_SLH_DSA_SHA2_128S", "SLH-DSA", true, 0},
		{"EXTERNAL_SYMMETRIC_ENCRYPTION", "AES", true, 256},
		{"CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED", "", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			a, ok := algoToAsset(tc.algo)
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v", ok, tc.ok)
			}
			if ok && (a.Algorithm != tc.want || a.KeySize != tc.size) {
				t.Errorf("got %s-%d, want %s-%d", a.Algorithm, a.KeySize, tc.want, tc.size)
			}
		})
	}
}
