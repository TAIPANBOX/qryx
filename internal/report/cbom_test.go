package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// TestCBOMBasicShape checks the overall CycloneDX document shape for a
// single asset: bomFormat/specVersion metadata, one component with the
// expected name, cryptoProperties, evidence occurrence, and a
// "crypto:"-prefixed bom-ref.
func TestCBOMBasicShape(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048, Primitive: model.PrimitiveSignature},
			Location: model.Location{File: "a.go", Line: 5},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh, Reason: "RSA is broken by a cryptographically relevant quantum computer (Shor)"},
		},
	}}

	var buf bytes.Buffer
	if err := CBOM(&buf, res, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}

	var doc cbomDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat=%q want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion=%q want 1.6", doc.SpecVersion)
	}
	if len(doc.Metadata.Tools) != 1 || doc.Metadata.Tools[0].Name != "qryx" {
		t.Errorf("tools=%+v want one qryx tool", doc.Metadata.Tools)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("got %d components, want 1: %+v", len(doc.Components), doc.Components)
	}

	comp := doc.Components[0]
	if comp.Type != "cryptographic-asset" {
		t.Errorf("type=%q want cryptographic-asset", comp.Type)
	}
	if comp.Name != "RSA-2048" {
		t.Errorf("name=%q want RSA-2048", comp.Name)
	}
	if comp.BOMRef == "" || !strings.HasPrefix(comp.BOMRef, "crypto:") {
		t.Errorf("bom-ref=%q want non-empty, crypto:-prefixed", comp.BOMRef)
	}
	if comp.CryptoProperties == nil || comp.CryptoProperties.AssetType != string(model.TypeAlgorithm) {
		t.Errorf("cryptoProperties=%+v want assetType=algorithm", comp.CryptoProperties)
	}
	if comp.Evidence == nil || len(comp.Evidence.Occurrences) != 1 || comp.Evidence.Occurrences[0].Location != "a.go" {
		t.Errorf("evidence=%+v want one occurrence at a.go", comp.Evidence)
	}
}

// TestCBOMBomRefUniqueAcrossRiskClasses pins the CycloneDX-spec-violation
// counterpart of the graph dedup fix in commit e06d605: a certificate that is
// both quantum-vulnerable and expired now produces two graph.AssetNode
// entries (risk class is part of node identity, see
// internal/graph/graph.go), so CBOM() must emit two components with distinct
// bom-ref values. Before bomRef() was updated to include risk class, both
// components hashed type|algorithm|keySize alone and collided on an
// identical bom-ref, which CycloneDX requires to be unique within a
// document.
func TestCBOMBomRefUniqueAcrossRiskClasses(t *testing.T) {
	cert := model.Asset{Type: model.TypeCertificate, Algorithm: "RSA", KeySize: 2048, Primitive: model.PrimitiveSignature}
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{
			Asset:    cert,
			Location: model.Location{File: "expired.badssl.com:443"},
			Evidence: `certificate "expired.badssl.com", RSA key`,
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh, Reason: "RSA is broken by a cryptographically relevant quantum computer (Shor)"},
		},
		{
			Asset:    cert,
			Location: model.Location{File: "expired.badssl.com:443"},
			Evidence: `certificate "expired.badssl.com" expired 2015-08-01`,
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskExpired, Severity: model.SeverityHigh, Reason: "certificate is past its NotAfter date"},
		},
	}}

	var buf bytes.Buffer
	if err := CBOM(&buf, res, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}

	var doc cbomDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2 (one per risk class): %+v", len(doc.Components), doc.Components)
	}

	refs := map[string]bool{}
	for _, c := range doc.Components {
		if c.BOMRef == "" {
			t.Errorf("component %+v has empty bom-ref", c)
		}
		refs[c.BOMRef] = true
	}
	if len(refs) != len(doc.Components) {
		t.Errorf("bom-ref values collided across components (CycloneDX requires bom-ref to be unique): %+v", doc.Components)
	}
}

// TestCBOMExcludesNonCryptographicAssetTypes pins that a CBOM, a
// CycloneDX Cryptography Bill of Materials, stays scoped to actual
// cryptography. An ai-usage finding (model.TypeAIModel) is an inventory
// fact, not a cryptographic asset, so it must not appear as a
// "cryptographic-asset" component; the real RSA finding alongside it must
// still appear normally.
func TestCBOMExcludesNonCryptographicAssetTypes(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048, Primitive: model.PrimitiveSignature},
			Location: model.Location{File: "a.go", Line: 5},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
		{
			Asset:    model.Asset{Type: model.TypeAIModel, Algorithm: "OpenAI SDK (python)", Primitive: model.PrimitiveUnknown},
			Location: model.Location{File: "agent.py", Line: 2},
			Source:   "aiusage",
			Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityInfo},
		},
	}}

	var buf bytes.Buffer
	if err := CBOM(&buf, res, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	var doc cbomDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("got %d components, want 1 (ai-usage excluded): %+v", len(doc.Components), doc.Components)
	}
	if doc.Components[0].Name != "RSA-2048" {
		t.Errorf("surviving component = %q, want RSA-2048", doc.Components[0].Name)
	}
}

// CycloneDX 1.6's closed vocabularies for the two fields this writer fills
// from qryx's own, wider, internal vocabulary. Copied from
// schema/bom-1.6.schema.json of CycloneDX/specification at tag 1.6
// (cryptoProperties.assetType and algorithmProperties.primitive), so the test
// needs no schema library and no network. If the spec version this writer
// emits ever moves, these lists move with it, in the same commit.
var (
	cdx16AssetTypes = map[string]bool{
		"algorithm": true, "certificate": true, "protocol": true, "related-crypto-material": true,
	}
	cdx16Primitives = map[string]bool{
		"drbg": true, "mac": true, "block-cipher": true, "stream-cipher": true, "signature": true,
		"hash": true, "pke": true, "xof": true, "kdf": true, "key-agree": true, "kem": true,
		"ae": true, "combiner": true, "other": true, "unknown": true,
	}
	cdx16ComponentTypes = map[string]bool{
		"application": true, "framework": true, "library": true, "container": true, "platform": true,
		"operating-system": true, "device": true, "device-driver": true, "firmware": true, "file": true,
		"machine-learning-model": true, "data": true, "cryptographic-asset": true,
	}
	cdx16ProtocolTypes = map[string]bool{"tls": true, "ssh": true, "ipsec": true, "ike": true, "sstp": true, "wpa": true, "other": true, "unknown": true}
)

// TestCBOMStaysInsideCycloneDX16Vocabulary is the test that would have caught
// POL-5 of the 1.0 proving run (2026-09-13): `qryx image --format cbom` on the
// tokenfuse image emitted primitive "encryption" (DES, 3DES, AES, EVP_CIPHER)
// and "key-exchange", and assetType "library", none of which is in the 1.6
// enums, so a stranger validating the document against the schema got nine
// errors. The source scan happened to emit only signature/hash/unknown and
// validated, which is why nothing here noticed. Every internal primitive and
// asset type goes through the writer, with the algorithm names the detectors
// actually emit, and every value that comes out must be one the schema names.
func TestCBOMStaysInsideCycloneDX16Vocabulary(t *testing.T) {
	// The graph keys an asset node by type, algorithm and key size, so one
	// algorithm name per primitive keeps every primitive visible in the
	// output rather than merged under the first one seen.
	byPrimitive := map[model.Primitive][]string{
		model.PrimitiveSignature:  {"RSA", "ECDSA", "Ed25519"},
		model.PrimitiveEncryption: {"AES", "DES", "3DES", "RC4", "RC2", "ChaCha20", "EVP_CIPHER"},
		model.PrimitiveHash:       {"SHA-1", "MD5", "HMAC"},
		model.PrimitiveKeyExch:    {"ECDH", "DH", "ML-KEM"},
		model.PrimitiveTLS:        {"TLS"},
		model.PrimitiveUnknown:    {"X"},
	}
	var findings []model.Finding
	line := 0
	add := func(at model.AssetType, a string, p model.Primitive) {
		line++
		findings = append(findings, model.Finding{
			Asset:    model.Asset{Type: at, Algorithm: a, Primitive: p},
			Location: model.Location{File: "x.go", Line: line},
			Source:   "test",
			Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityNone},
		})
	}
	for p, algos := range byPrimitive {
		for _, a := range algos {
			add(model.TypeAlgorithm, a, p)
		}
	}
	// The other asset types, with the algorithm names the detectors give them.
	add(model.TypeKey, "enclave-key", model.PrimitiveUnknown)
	add(model.TypeKey, "AES-256", model.PrimitiveEncryption)
	add(model.TypeCertificate, "RSA-cert", model.PrimitiveSignature)
	add(model.TypeProtocol, "TLS-endpoint", model.PrimitiveTLS)
	add(model.TypeProtocol, "no-attestation", model.PrimitiveUnknown)
	add(model.TypeProtocol, "hash-chain-broken", model.PrimitiveHash)
	add(model.TypeLibrary, "libcrypto", model.PrimitiveUnknown)
	add(model.TypeLibrary, "openssl", model.PrimitiveEncryption)
	res := &scan.Result{Root: "test", Findings: findings}
	var buf bytes.Buffer
	if err := CBOM(&buf, res, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			Type             string `json:"type"`
			Name             string `json:"name"`
			CryptoProperties *struct {
				AssetType      string `json:"assetType"`
				AlgorithmProps *struct {
					Primitive string `json:"primitive"`
				} `json:"algorithmProperties"`
				ProtocolProps *struct {
					Type string `json:"type"`
				} `json:"protocolProperties"`
				RelatedProps *struct {
					Type string `json:"type"`
				} `json:"relatedCryptoMaterialProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Components) == 0 {
		t.Fatal("no components: the matrix produced nothing, so this proved nothing")
	}
	for _, c := range doc.Components {
		if !cdx16ComponentTypes[c.Type] {
			t.Errorf("%s: component type %q is not in CycloneDX 1.6", c.Name, c.Type)
		}
		if c.Type != "cryptographic-asset" {
			if c.CryptoProperties != nil {
				t.Errorf("%s: a %q component must not carry cryptoProperties", c.Name, c.Type)
			}
			continue
		}
		if c.CryptoProperties == nil {
			t.Errorf("%s: a cryptographic-asset needs cryptoProperties", c.Name)
			continue
		}
		cp := c.CryptoProperties
		if !cdx16AssetTypes[cp.AssetType] {
			t.Errorf("%s: assetType %q is not in CycloneDX 1.6 %v", c.Name, cp.AssetType, keys(cdx16AssetTypes))
		}
		switch cp.AssetType {
		case "algorithm":
			if cp.AlgorithmProps == nil || !cdx16Primitives[cp.AlgorithmProps.Primitive] {
				got := "<none>"
				if cp.AlgorithmProps != nil {
					got = cp.AlgorithmProps.Primitive
				}
				t.Errorf("%s: primitive %q is not in CycloneDX 1.6 %v", c.Name, got, keys(cdx16Primitives))
			}
		case "protocol":
			if cp.AlgorithmProps != nil {
				t.Errorf("%s: a protocol asset carries algorithmProperties; the schema wants protocolProperties", c.Name)
			}
			if cp.ProtocolProps == nil || !cdx16ProtocolTypes[cp.ProtocolProps.Type] {
				t.Errorf("%s: protocol asset without a valid protocolProperties.type", c.Name)
			}
		case "related-crypto-material":
			if cp.AlgorithmProps != nil {
				t.Errorf("%s: key material carries algorithmProperties", c.Name)
			}
			if cp.RelatedProps == nil || cp.RelatedProps.Type == "" {
				t.Errorf("%s: key material without relatedCryptoMaterialProperties.type", c.Name)
			}
		}
	}
}

// TestCBOMPrimitiveMappingIsSpecific pins the mapping the boundary applies, so
// a lazy "everything is other" cannot pass the vocabulary test above.
func TestCBOMPrimitiveMappingIsSpecific(t *testing.T) {
	cases := []struct {
		algo string
		prim model.Primitive
		want string
	}{
		{"AES", model.PrimitiveEncryption, "block-cipher"},
		{"DES", model.PrimitiveEncryption, "block-cipher"},
		{"3DES", model.PrimitiveEncryption, "block-cipher"},
		{"RC2", model.PrimitiveEncryption, "block-cipher"},
		{"RC4", model.PrimitiveEncryption, "stream-cipher"},
		{"ChaCha20", model.PrimitiveEncryption, "stream-cipher"},
		{"RSA", model.PrimitiveEncryption, "pke"},
		{"EVP_CIPHER", model.PrimitiveEncryption, "other"},
		{"ECDH", model.PrimitiveKeyExch, "key-agree"},
		{"DH", model.PrimitiveKeyExch, "key-agree"},
		{"ML-KEM", model.PrimitiveKeyExch, "kem"},
		{"RSA", model.PrimitiveSignature, "signature"},
		{"SHA-1", model.PrimitiveHash, "hash"},
		{"HMAC", model.PrimitiveHash, "mac"},
		{"X", model.PrimitiveUnknown, "unknown"},
	}
	for _, c := range cases {
		if got := cdxPrimitive(c.algo, c.prim); got != c.want {
			t.Errorf("cdxPrimitive(%q, %q) = %q, want %q", c.algo, c.prim, got, c.want)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
