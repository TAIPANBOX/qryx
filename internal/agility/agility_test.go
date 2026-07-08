package agility

import (
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
		{"goast", Low},
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
