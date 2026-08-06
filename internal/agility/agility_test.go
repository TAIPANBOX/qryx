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
