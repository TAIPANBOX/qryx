package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func TestHTMLEscapesAndRenders(t *testing.T) {
	res := &scan.Result{
		Root:        "demo",
		FilesWalked: 1,
		Findings: []model.Finding{
			{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "<script>alert(1)</script>.go", Line: 3}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh, Reason: "broken"}},
			{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		},
	}

	var buf bytes.Buffer
	if err := HTML(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Basic structural invariants of a complete page.
	for _, want := range []string{"<!DOCTYPE html>", "<table>", "</html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	// Untrusted location must be escaped, never emitted raw.
	if strings.Contains(out, "<script>alert(1)</script>.go") {
		t.Error("raw <script> from a file path leaked into the HTML")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected the script tag to appear escaped")
	}
	// One row per unique asset (MD5, RSA-2048).
	if n := strings.Count(out, `class="badge`); n != 2 {
		t.Errorf("got %d asset rows, want 2", n)
	}
}
