package graph

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func TestBuildDedupsAssetAcrossSources(t *testing.T) {
	findings := []model.Finding{
		// Same RSA-2048 from three places across two sources.
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "a.go", Line: 10}, Source: "goast", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "b.go", Line: 3}, Source: "goast", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "host:443"}, Source: "tls-probe", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		// A weak MD5 elsewhere.
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "a.go", Line: 4}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
	}

	nodes := Build(findings)
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}

	var rsa *AssetNode
	for i := range nodes {
		if nodes[i].Asset.Algorithm == "RSA" {
			rsa = &nodes[i]
		}
	}
	if rsa == nil {
		t.Fatal("no RSA node")
	}
	if len(rsa.Occurrences) != 3 {
		t.Errorf("RSA occurrences = %d, want 3", len(rsa.Occurrences))
	}
}

func TestBuildKeepsHighestSeverityAndNormalizes(t *testing.T) {
	findings := []model.Finding{
		// "SHA1" and "SHA-1" must unify; medium then high -> node keeps high.
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA1"}, Location: model.Location{File: "a.go", Line: 1}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityMedium}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-1"}, Location: model.Location{File: "b.go", Line: 2}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
	}
	nodes := Build(findings)
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (SHA1/SHA-1 unify)", len(nodes))
	}
	if nodes[0].Risk.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", nodes[0].Risk.Severity)
	}
	if len(nodes[0].Occurrences) != 2 {
		t.Errorf("occurrences = %d, want 2", len(nodes[0].Occurrences))
	}
}

func TestBuildDedupsIdenticalOccurrence(t *testing.T) {
	f := model.Finding{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "AES"}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskNone}}
	nodes := Build([]model.Finding{f, f, f})
	if len(nodes) != 1 || len(nodes[0].Occurrences) != 1 {
		t.Fatalf("identical occurrences not deduped: nodes=%d occ=%d", len(nodes), len(nodes[0].Occurrences))
	}
}

func TestBuildMergesTagsAcrossOccurrences(t *testing.T) {
	// Same RSA key found from two cloud sources with different tags — node-level
	// Tags must be the union.
	findings := []model.Finding{
		{
			Asset:    model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: 2048},
			Location: model.Location{File: "arn:kms:key/1"},
			Source:   "aws-kms",
			Tags:     map[string]string{"Owner": "security", "env": "prod"},
		},
		{
			Asset:    model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: 2048},
			Location: model.Location{File: "arn:acm:cert/1"},
			Source:   "aws-acm",
			Tags:     map[string]string{"team": "infra"},
		},
	}
	nodes := Build(findings)
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	n := nodes[0]
	if n.Tags["Owner"] != "security" {
		t.Errorf("Owner tag missing or wrong: %v", n.Tags)
	}
	if n.Tags["team"] != "infra" {
		t.Errorf("team tag missing: %v", n.Tags)
	}
	if len(n.Occurrences) != 2 {
		t.Errorf("want 2 occurrences, got %d", len(n.Occurrences))
	}
	// Each occurrence carries its own tags — find by source, not by index.
	var kmsOcc *Occurrence
	for i := range n.Occurrences {
		if n.Occurrences[i].Source == "aws-kms" {
			kmsOcc = &n.Occurrences[i]
			break
		}
	}
	if kmsOcc == nil || kmsOcc.Tags["Owner"] != "security" {
		t.Errorf("aws-kms occurrence Owner tag wrong: %v", kmsOcc)
	}
}
