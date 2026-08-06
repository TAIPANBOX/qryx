package agility

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
)

func node(algo string, size int, prim model.Primitive, sources ...string) graph.AssetNode {
	n := graph.AssetNode{Asset: model.Asset{Type: model.TypeKey, Algorithm: algo, KeySize: size, Primitive: prim}}
	for i, s := range sources {
		n.Occurrences = append(n.Occurrences, graph.Occurrence{
			Location: model.Location{File: "f", Line: i + 1}, Source: s,
		})
	}
	if len(sources) == 0 {
		n.Occurrences = append(n.Occurrences, graph.Occurrence{Location: model.Location{File: "f", Line: 1}, Source: "goast"})
	}
	return n
}

func TestTargetMapping(t *testing.T) {
	tests := []struct {
		algo string
		size int
		prim model.Primitive
		want string
		ok   bool
	}{
		{"RSA", 2048, model.PrimitiveSignature, "ML-DSA (FIPS 204)", true},
		{"RSA", 2048, model.PrimitiveEncryption, "ML-KEM (FIPS 203)", true},
		{"ECDSA", 0, model.PrimitiveSignature, "ML-DSA (FIPS 204)", true},
		{"ECDH", 0, model.PrimitiveKeyExch, "ML-KEM (FIPS 203)", true},
		{"Ed25519", 0, model.PrimitiveSignature, "ML-DSA (FIPS 204)", true},
		{"ed25519", 0, model.PrimitiveSignature, "ML-DSA (FIPS 204)", true},
		{"ED25519", 0, model.PrimitiveSignature, "ML-DSA (FIPS 204)", true},
		{"MD5", 0, model.PrimitiveHash, "SHA-256 / SHA-384", true},
		{"DES", 0, model.PrimitiveEncryption, "AES-256-GCM", true},
		{"AES", 128, model.PrimitiveEncryption, "AES-256-GCM", true},
		{"AES", 256, model.PrimitiveEncryption, "", false},
		// Size 0 is a size nobody read. Only a size that was read, and that
		// clears 256, exempts an AES asset from the plan. See
		// TestUnknownSizeAESIsPlannedNotSkipped.
		{"AES", 0, model.PrimitiveEncryption, "AES-256-GCM", true},
		{"ML-KEM", 0, model.PrimitiveKeyExch, "", false},
		{"SHA-512", 0, model.PrimitiveHash, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			a, ok := Assess(node(tc.algo, tc.size, tc.prim))
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if ok && a.Target != tc.want {
				t.Errorf("target=%q want %q", a.Target, tc.want)
			}
		})
	}
}

func TestAgilityBySource(t *testing.T) {
	tests := []struct {
		source string
		want   Level
	}{
		{"aws-kms", High},
		{"gcp-kms", High},
		{"azure-keyvault", High},
		{"aws-acm", Medium},
		{"tlsconfig", Medium},
		{"tls-probe", Medium},
		{"certfile", Medium},
		{"deps", Medium},
		{"terraform", Medium},
		{"goast", Low},
		{"cryptocall", Low},
		{"rust", Low},
		{"hardcoded", Low},
		{"binary", Low},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			a, ok := Assess(node("RSA", 2048, model.PrimitiveSignature, tc.source))
			if !ok {
				t.Fatal("expected migration needed")
			}
			if a.Agility != tc.want {
				t.Errorf("agility=%q want %q", a.Agility, tc.want)
			}
		})
	}
}

// TestTerraformDeclaredAssetIsConfigAgility pins the level for an asset qryx
// only ever saw as an HCL declaration. A `aws_kms_key` or a
// `google_kms_crypto_key` in Terraform is changed by editing a key-spec
// argument and running `apply`, which is what Medium means here; scoring it
// Low said "code change + redeploy" about a file that is configuration. The
// same physical key read back through the AWS or GCP connector scores High,
// so the old answer also made one key's difficulty depend on which connector
// happened to see it.
func TestTerraformDeclaredAssetIsConfigAgility(t *testing.T) {
	a, ok := Assess(node("RSA", 2048, model.PrimitiveSignature, "terraform"))
	if !ok {
		t.Fatal("expected migration needed")
	}
	if a.Agility != Medium {
		t.Errorf("agility=%q want %q (an HCL declaration is a config change, not a code change)", a.Agility, Medium)
	}
}

// TestEffortNoteNamesAnUnrecognizedSource covers the second half of the same
// bug: dominantAgility only recorded a source name inside the branch that
// recognized it, so an unlisted source was dropped from the effort note as
// well as from the ranking, and the note rendered an empty parenthesis. The
// note is the only place the report says where an asset was seen, so an
// unknown source is exactly the case where it must still say something.
func TestEffortNoteNamesAnUnrecognizedSource(t *testing.T) {
	a, ok := Assess(node("RSA", 2048, model.PrimitiveSignature, "some-future-connector"))
	if !ok {
		t.Fatal("expected migration needed")
	}
	if !strings.Contains(a.Effort, "some-future-connector") {
		t.Errorf("effort=%q does not name the source it came from", a.Effort)
	}
	if strings.Contains(a.Effort, "()") {
		t.Errorf("effort=%q renders an empty parenthesis", a.Effort)
	}
}

// TestEffortNoteOmitsTheParentheticalWhenThereIsNoSource is the degenerate
// case of the same rendering: with nothing to name, the note should drop the
// parenthetical rather than print an empty one.
func TestEffortNoteOmitsTheParentheticalWhenThereIsNoSource(t *testing.T) {
	n := graph.AssetNode{Asset: model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: 2048, Primitive: model.PrimitiveSignature}}
	a, ok := Assess(n)
	if !ok {
		t.Fatal("expected migration needed")
	}
	// " (" is the source parenthetical; "occurrence(s)" has no space before
	// its own bracket.
	if strings.Contains(a.Effort, " (") {
		t.Errorf("effort=%q renders a source parenthetical with no source to put in it", a.Effort)
	}
}

// TestUnrecognizedSourceStillCountsAsLeastAgile keeps the fallback consistent
// with the rule beside it. An unknown source alone already meant "assume
// hardest"; skipping it when a known source sat next to it meant the same
// occurrence was treated as hardest or as absent depending on its company, so
// an asset seen in a KMS *and* somewhere qryx could not rank came back High.
func TestUnrecognizedSourceStillCountsAsLeastAgile(t *testing.T) {
	a, ok := Assess(node("RSA", 2048, model.PrimitiveSignature, "aws-kms", "some-future-connector"))
	if !ok {
		t.Fatal("expected migration needed")
	}
	if a.Agility != Low {
		t.Errorf("agility=%q want %q (an unrankable occurrence is assumed hardest, alone or not)", a.Agility, Low)
	}
}

func TestLeastAgileWinsAcrossSources(t *testing.T) {
	// An RSA key seen in both KMS (high) and code (low) → least agile = low.
	a, ok := Assess(node("RSA", 2048, model.PrimitiveSignature, "aws-kms", "goast"))
	if !ok {
		t.Fatal("expected migration needed")
	}
	if a.Agility != Low {
		t.Errorf("agility=%q want low (code occurrence dominates)", a.Agility)
	}
}

func TestRSAUnder2048Rationale(t *testing.T) {
	a, ok := Assess(node("RSA", 1024, model.PrimitiveSignature, "goast"))
	if !ok {
		t.Fatal("expected migration needed")
	}
	if a.Target != "ML-DSA (FIPS 204)" {
		t.Errorf("target=%q", a.Target)
	}
	// rationale should mention the interim RSA-3072 step
	if a.Rationale == "" {
		t.Error("expected non-empty rationale for RSA-1024")
	}
}

// TestUnknownSizeAESIsPlannedNotSkipped holds the half of Assess that decides
// whether an asset reaches the migration plan at all. `ok=false` says "this
// asset already meets the bar", and an AES key whose size the scan never read
// has not been shown to meet anything: `KeySize == 0` is an unread size, not a
// 256-bit one.
//
// The unknown is the common shape here, not an edge case. Eight of the twelve
// places that build an AES asset leave the size at zero: Azure Key Vault `oct`
// and `oct-HSM` keys, where the length is not derivable from public metadata
// while both Key Vault and Managed HSM accept 128 and 192; the same key in
// Terraform; a `crypto/aes` import; the `AES_` and `EVP_aes_` symbol rules in
// binscan; and three identifier patterns in the rust and cryptocall detectors.
// Two of those match text naming the size on the very line they matched
// (`Aes128Gcm`, `createCipheriv('aes-128-cbc', ...)`), so the asset skipped
// here can be a literal AES-128.
func TestUnknownSizeAESIsPlannedNotSkipped(t *testing.T) {
	a, ok := Assess(node("AES", 0, model.PrimitiveEncryption, "cryptocall"))
	if !ok {
		t.Fatal("AES with no size read was reported as needing no migration; size 0 is a size nobody read, not an AES-256")
	}
	if a.Target != "AES-256-GCM" {
		t.Errorf("target=%q, want AES-256-GCM", a.Target)
	}
}

// TestAESRationaleStatesOnlyTheSizeThatWasRead holds the other half. Listing a
// sizeless AES asset is only an improvement if the line beside it says why it
// is listed; a rationale reading "AES below 256 bits is below the CNSA 2.0
// minimum" over a key whose length was never read is the same defect pointed
// the other way, and it is the sentence an operator would act on.
//
// The assertions pin the property rather than the wording: the three cases must
// be distinguishable from each other, the read size must appear in its own
// rationale, and neither the unread nor the compliant case may assert a
// shortfall that nothing established.
func TestAESRationaleStatesOnlyTheSizeThatWasRead(t *testing.T) {
	unread := rationale(model.Asset{Algorithm: "AES"})
	below := rationale(model.Asset{Algorithm: "AES", KeySize: 128})
	atBar := rationale(model.Asset{Algorithm: "AES", KeySize: 256})

	if unread == below {
		t.Errorf("the rationale for an AES key with no size read is identical to the AES-128 one (%q), so it asserts a size the scan never established", unread)
	}
	if !saysSizeWasNotRead(unread) {
		t.Errorf("rationale for unread-size AES does not say the size is what is missing: %q", unread)
	}
	if !strings.Contains(below, "128") {
		t.Errorf("rationale for AES-128 does not name the size that was read: %q", below)
	}
	// Unreachable through Assess today, since target() exempts >= 256 before
	// rationale() is called. It is asserted anyway because the string is wrong
	// where it sits, and the next caller inherits it.
	if claimsBelowTheMinimum(atBar) {
		t.Errorf("rationale for AES-256 says it is below the CNSA 2.0 minimum, which it is not: %q", atBar)
	}
}

// saysSizeWasNotRead reports whether a rationale admits the key size was never
// established, in any phrasing a rewrite might reasonably reach for.
func saysSizeWasNotRead(s string) bool {
	l := strings.ToLower(s)
	if !strings.Contains(l, "size") && !strings.Contains(l, "length") {
		return false
	}
	for _, marker := range []string{"could not", "did not", "not determine", "never read", "unknown", "not established"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

// claimsBelowTheMinimum reports whether a rationale asserts this key falls short
// of the CNSA 2.0 bar, as opposed to describing where the bar is.
func claimsBelowTheMinimum(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "is below") || strings.Contains(l, "below the")
}

// TestEd25519MapsLikeOtherSignatureAlgorithms ensures Ed25519 gets the same
// migration target and a non-empty rationale, consistent with how the other
// classical signature algorithms (ECDSA/DSA) are mapped in target()/rationale().
func TestEd25519MapsLikeOtherSignatureAlgorithms(t *testing.T) {
	for _, algo := range []string{"Ed25519", "ed25519", "ED25519"} {
		t.Run(algo, func(t *testing.T) {
			ed, ok := Assess(node(algo, 0, model.PrimitiveSignature, "goast"))
			if !ok {
				t.Fatal("expected migration needed for Ed25519")
			}
			ecdsa, _ := Assess(node("ECDSA", 0, model.PrimitiveSignature, "goast"))
			if ed.Target != ecdsa.Target {
				t.Errorf("Ed25519 target=%q, want same as ECDSA (%q)", ed.Target, ecdsa.Target)
			}
			if ed.Rationale == "" {
				t.Error("expected non-empty rationale for Ed25519")
			}
		})
	}
}
