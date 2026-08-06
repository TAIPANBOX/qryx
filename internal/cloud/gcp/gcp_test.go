package gcp

import (
	"context"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

type fakeLister struct {
	versions []keyVersion
	skipped  []string
}

func (f fakeLister) list(_ context.Context, _, _ string) ([]keyVersion, []string, error) {
	return f.versions, f.skipped, nil
}

func TestScanWithMapsAlgorithms(t *testing.T) {
	l := fakeLister{versions: []keyVersion{
		{Name: "projects/p/.../v1", Algorithm: "RSA_SIGN_PKCS1_2048_SHA256"},
		{Name: "projects/p/.../v2", Algorithm: "EC_SIGN_P256_SHA256"},
		{Name: "projects/p/.../v3", Algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION"},
		{Name: "projects/p/.../v4", Algorithm: "PQ_SIGN_ML_DSA_65"},
		{Name: "projects/p/.../v5", Algorithm: "CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED"}, // dropped
	}}

	got, _, err := scanWith(context.Background(), l, "p", "global")
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

func TestScanWithLabelsPopulated(t *testing.T) {
	l := fakeLister{versions: []keyVersion{
		{Name: "projects/p/.../v1", Algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION", Labels: map[string]string{"team": "platform"}},
	}}
	got, _, err := scanWith(context.Background(), l, "p", "global")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Tags["team"] != "platform" {
		t.Errorf("Labels not propagated as Tags: %v", got[0].Tags)
	}
}

// recordingLister remembers what scope it was asked for.
type recordingLister struct{ project, location string }

func (r *recordingLister) list(_ context.Context, project, location string) ([]keyVersion, []string, error) {
	r.project, r.location = project, location
	return nil, nil, nil
}

// TestScanDefaultsToEveryKMSLocation pins the scope of a plain `qryx gcp
// --project X`. It used to be a single location defaulting to "global", and
// Cloud KMS key rings are overwhelmingly regional, so that inventoried almost
// nothing in a real project and reported the result as a clean one. The API
// takes locations/- as a wildcard for ListKeyRings, so the narrow scope was a
// choice rather than a constraint.
func TestScanDefaultsToEveryKMSLocation(t *testing.T) {
	tests := []struct {
		name string
		give string
		want string
	}{
		{"no location given", "", AllLocations},
		{"an explicit location still narrows the scan", "europe-west1", "europe-west1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var l recordingLister
			if _, _, err := scanWith(context.Background(), &l, "p", tc.give); err != nil {
				t.Fatal(err)
			}
			if l.location != tc.want {
				t.Errorf("lister asked for location %q, want %q", l.location, tc.want)
			}
		})
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
