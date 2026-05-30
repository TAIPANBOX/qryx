package azure

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func boolPtr(b bool) *bool                        { return &b }
func timePtr(t time.Time) *time.Time              { return &t }
func keyTypePtr(k azkeys.KeyType) *azkeys.KeyType { return &k }

type fakeLister struct {
	items []keyItem
	keys  map[string]*azkeys.JSONWebKey
}

func (f fakeLister) list(_ context.Context) ([]keyItem, error) {
	return f.items, nil
}

func (f fakeLister) getKey(_ context.Context, name, _ string) (*azkeys.JSONWebKey, error) {
	return f.keys[name], nil
}

// rsaModulus returns n zero bytes to represent an RSA key of n*8 bits.
func rsaModulus(bits int) []byte { return make([]byte, bits/8) }

func TestScanWithMapsKeyTypes(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	items := []keyItem{
		{ID: "https://v.azure.net/keys/rsa/1", Name: "rsa", Version: "1"},
		{ID: "https://v.azure.net/keys/ec/1", Name: "ec", Version: "1"},
		{ID: "https://v.azure.net/keys/oct/1", Name: "oct", Version: "1"},
		{ID: "https://v.azure.net/keys/expired/1", Name: "expired", Version: "1",
			Attrs: &azkeys.KeyAttributes{Expires: timePtr(past)}},
		{ID: "https://v.azure.net/keys/disabled/1", Name: "disabled", Version: "1",
			Attrs: &azkeys.KeyAttributes{Enabled: boolPtr(false)}},
	}
	keys := map[string]*azkeys.JSONWebKey{
		"rsa":     {Kty: keyTypePtr(azkeys.KeyTypeRSA), N: rsaModulus(2048)},
		"ec":      {Kty: keyTypePtr(azkeys.KeyTypeEC)},
		"oct":     {Kty: keyTypePtr(azkeys.KeyTypeOct)},
		"expired": {Kty: keyTypePtr(azkeys.KeyTypeRSA), N: rsaModulus(3072)},
	}

	got, err := scanWith(context.Background(), fakeLister{items, keys})
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string][]model.Finding{}
	for _, f := range got {
		// Extract key name from the ID URL segment.
		for _, item := range items {
			if item.ID == f.Location.File {
				byName[item.Name] = append(byName[item.Name], f)
			}
		}
	}

	// RSA-2048 should be mapped correctly.
	if rsaFindings, ok := byName["rsa"]; !ok || rsaFindings[0].Asset.Algorithm != "RSA" || rsaFindings[0].Asset.KeySize != 2048 {
		t.Errorf("RSA mapping wrong: %+v", byName["rsa"])
	}
	// EC → ECDSA.
	if ecFindings, ok := byName["ec"]; !ok || ecFindings[0].Asset.Algorithm != "ECDSA" {
		t.Errorf("EC mapping wrong: %+v", byName["ec"])
	}
	// oct → AES.
	if octFindings, ok := byName["oct"]; !ok || octFindings[0].Asset.Algorithm != "AES" {
		t.Errorf("oct mapping wrong: %+v", byName["oct"])
	}
	// expired key should produce an expiry risk finding.
	var sawExpired bool
	for _, f := range byName["expired"] {
		if f.Risk.Class == model.RiskExpired {
			sawExpired = true
		}
	}
	if !sawExpired {
		t.Error("expired key did not produce RiskExpired finding")
	}
	// disabled key must be skipped entirely.
	if _, ok := byName["disabled"]; ok {
		t.Error("disabled key should be skipped")
	}
}

func strPtr(s string) *string { return &s }

func TestScanWithTagsPopulated(t *testing.T) {
	items := []keyItem{{
		ID:      "https://v.azure.net/keys/tagged/1",
		Name:    "tagged",
		Version: "1",
		Tags:    map[string]*string{"Owner": strPtr("infra-team")},
	}}
	keys := map[string]*azkeys.JSONWebKey{"tagged": {Kty: keyTypePtr(azkeys.KeyTypeEC)}}
	got, err := scanWith(context.Background(), fakeLister{items, keys})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Tags["Owner"] != "infra-team" {
		t.Errorf("Tags not propagated: %v", got[0].Tags)
	}
}

func TestKeyTypeToAsset(t *testing.T) {
	tests := []struct {
		kty      azkeys.KeyType
		n        []byte
		wantAlgo string
		wantSize int
		ok       bool
	}{
		{azkeys.KeyTypeRSA, rsaModulus(4096), "RSA", 4096, true},
		{azkeys.KeyTypeRSAHSM, rsaModulus(2048), "RSA", 2048, true},
		{azkeys.KeyTypeEC, nil, "ECDSA", 0, true},
		{azkeys.KeyTypeECHSM, nil, "ECDSA", 0, true},
		{azkeys.KeyTypeOct, nil, "AES", 0, true},
		{azkeys.KeyTypeOctHSM, nil, "AES", 0, true},
		{"unknown-type", nil, "", 0, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.kty), func(t *testing.T) {
			a, ok := keyTypeToAsset(tc.kty, tc.n)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if ok && (a.Algorithm != tc.wantAlgo || a.KeySize != tc.wantSize) {
				t.Errorf("got %s-%d, want %s-%d", a.Algorithm, a.KeySize, tc.wantAlgo, tc.wantSize)
			}
		})
	}
}
