package policy

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
)

// maxSeverity is read case-insensitively, gates strictly above its level, and
// each level is its own boundary: an asset AT the maximum passes, one level
// above fails.
func TestMaxSeverityEachLevelIsItsOwnBoundary(t *testing.T) {
	levels := []struct {
		word string
		sev  model.Severity
	}{
		{"LOW", model.SeverityLow},
		{"Medium", model.SeverityMedium},
		{"high", model.SeverityHigh},
	}
	for _, l := range levels {
		at := node("X", 0, model.RiskWeak, l.sev)
		above := node("Y", 0, model.RiskWeak, l.sev+1)
		vs := Evaluate(Policy{MaxSeverity: l.word}, []graph.AssetNode{at, above})
		var hits []string
		for _, v := range vs {
			if v.Rule == "max-severity" {
				hits = append(hits, v.Asset)
			}
		}
		if len(hits) != 1 || hits[0] != "Y" {
			t.Errorf("maxSeverity %q: violations on %v, want only the asset above it", l.word, hits)
		}
	}
	// critical is the top: nothing can exceed it.
	if vs := Evaluate(Policy{MaxSeverity: "critical"}, []graph.AssetNode{node("Z", 0, model.RiskWeak, model.SeverityCritical)}); len(vs) != 0 {
		t.Errorf("maxSeverity critical raised %+v", vs)
	}
	if _, ok := parseSeverity("severe"); ok {
		t.Error("an unknown severity word was accepted")
	}
}
