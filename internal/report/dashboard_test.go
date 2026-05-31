package report

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func dashboardFixture() *scan.Result {
	findings := []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 1024, Primitive: model.PrimitiveSignature}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityCritical}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5", Primitive: model.PrimitiveHash}, Location: model.Location{File: "b.go", Line: 2}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "AES", KeySize: 256, Primitive: model.PrimitiveEncryption}, Location: model.Location{File: "c.go", Line: 3}, Source: "goast", Risk: model.Risk{Class: model.RiskNone}},
	}
	return &scan.Result{Root: "testdata", Findings: findings}
}

func renderDashboard(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Dashboard(&buf, dashboardFixture(), "test-1.0"); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestDashboardContent(t *testing.T) {
	html := renderDashboard(t)

	for _, want := range []string{
		"<!DOCTYPE html>",
		"Governance Dashboard",
		"qryx test-1.0",
		"evidence sha256:",
		"Top remediation priorities",
		"RSA-1024",          // ranked priority
		"ML-DSA (FIPS 204)", // its target
		"Non-compliant assets",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestDashboardPrioritiesCapped(t *testing.T) {
	// Build many distinct weak assets; priorities must cap at the max.
	var findings []model.Finding
	sizes := []int{512, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 2816, 3328}
	for i, s := range sizes {
		findings = append(findings, model.Finding{
			Asset:    model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: s, Primitive: model.PrimitiveSignature},
			Location: model.Location{File: "f.go", Line: i + 1},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		})
	}
	var buf bytes.Buffer
	if err := Dashboard(&buf, &scan.Result{Root: "t", Findings: findings}, "v"); err != nil {
		t.Fatal(err)
	}
	// Each priority row renders one "→" target cell; count must not exceed cap.
	if got := strings.Count(buf.String(), `<span class="arrow">`); got > dashboardMaxPriorities {
		t.Errorf("priorities not capped: %d > %d", got, dashboardMaxPriorities)
	}
}

func TestDashboardScoreMatchesEvidence(t *testing.T) {
	ev, err := buildEvidence(dashboardFixture(), "v")
	if err != nil {
		t.Fatal(err)
	}
	html := renderDashboard(t)
	// The dashboard must show the same compliance score as the evidence summary.
	if !strings.Contains(html, strconv.Itoa(ev.Summary.ScorePct)+"%") {
		t.Errorf("dashboard score != evidence score (%d%%)", ev.Summary.ScorePct)
	}
}
