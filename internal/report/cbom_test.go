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
// entries (risk class is part of node identity — see
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
