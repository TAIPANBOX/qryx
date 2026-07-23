package model

import "testing"

// TestAssetTypeIsCryptographic pins which asset types the crypto-specific
// reports (CBOM/CNSA/NCSC) are allowed to grade. TypeAIModel must stay false:
// it is an inventory fact, not a cryptographic asset, and the reports that
// key on IsCryptographic rely on this to keep from mislabeling it (see
// internal/report/cbom.go, cnsa.go, ncsc.go).
func TestAssetTypeIsCryptographic(t *testing.T) {
	tests := []struct {
		typ  AssetType
		want bool
	}{
		{TypeAlgorithm, true},
		{TypeKey, true},
		{TypeCertificate, true},
		{TypeProtocol, true},
		{TypeLibrary, true},
		{TypeAIModel, false},
		{AssetType("something-future-and-unreviewed"), false},
	}
	for _, tc := range tests {
		if got := tc.typ.IsCryptographic(); got != tc.want {
			t.Errorf("AssetType(%q).IsCryptographic() = %v, want %v", tc.typ, got, tc.want)
		}
	}
}
