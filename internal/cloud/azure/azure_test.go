package azure

import (
	"context"
	"fmt"
	"strings"
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
	deny  map[string]bool // key name -> GetKey is forbidden (keys/list without keys/get)
}

func (f fakeLister) list(_ context.Context) ([]keyItem, error) {
	return f.items, nil
}

func (f fakeLister) getKey(_ context.Context, name, _ string) (*azkeys.JSONWebKey, error) {
	if f.deny[name] {
		return nil, fmt.Errorf("Forbidden: the vault policy does not grant keys/get on %s", name)
	}
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

	got, _, err := scanWith(context.Background(), fakeLister{items: items, keys: keys})
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
	got, _, err := scanWith(context.Background(), fakeLister{items: items, keys: keys})
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

// TestScanWithSkipsAKeyItCannotGet pins that a common Key Vault policy does
// not kill the inventory. Granting keys/list without keys/get is ordinary, and
// the connector used to return the first GetKey error, so the scan died on key
// one and the operator got nothing from a vault it could partly read. The
// skip is only honest if it is reported, so unreadable keys come back
// alongside the findings and the CLI prints them.
func TestScanWithSkipsAKeyItCannotGet(t *testing.T) {
	items := []keyItem{
		{ID: "https://v.azure.net/keys/denied/1", Name: "denied", Version: "1"},
		{ID: "https://v.azure.net/keys/readable/1", Name: "readable", Version: "1"},
	}
	keys := map[string]*azkeys.JSONWebKey{
		"readable": {Kty: keyTypePtr(azkeys.KeyTypeRSA), N: rsaModulus(3072)},
	}
	got, skipped, err := scanWith(context.Background(), fakeLister{items: items, keys: keys, deny: map[string]bool{"denied": true}})
	if err != nil {
		t.Fatalf("one forbidden key ended the whole inventory: %v", err)
	}
	if len(got) != 1 || got[0].Asset.KeySize != 3072 {
		t.Errorf("got %+v, want the one readable RSA-3072 key", got)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "denied") {
		t.Errorf("skipped=%v, want one entry naming the key it could not read", skipped)
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
