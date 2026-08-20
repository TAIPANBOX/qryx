package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Human is the output of `qryx scan`, and none of it had ever been run.
//
// The line that matters is the one that is hardest to see is wrong: the
// summary counts. They are read off a map by risk class, and a class that
// stops being counted still prints, as a zero. Nothing about "0
// quantum-vulnerable" looks like a defect. It looks like good news.

func finding(algo string, bits int, class model.RiskClass, sev model.Severity, file string, line int) model.Finding {
	return model.Finding{
		Asset:    model.Asset{Type: model.TypeKey, Algorithm: algo, KeySize: bits},
		Location: model.Location{File: file, Line: line},
		Source:   "test",
		Risk:     model.Risk{Class: class, Severity: sev, Reason: "because"},
	}
}

func TestAnEmptyScanSaysSoRatherThanPrintingAnEmptyTable(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, &scan.Result{Root: "/src", FilesWalked: 12})
	out := buf.String()

	if !strings.Contains(out, "No cryptographic assets detected") {
		t.Fatalf("an empty scan did not say so:\n%s", out)
	}
	if strings.Contains(out, "SEVERITY") {
		t.Fatalf("an empty scan printed a table header with no rows under it, "+
			"which reads as a truncated report rather than a clean tree:\n%s", out)
	}
	if !strings.Contains(out, "12 sources scanned") {
		t.Fatalf("the file count is missing, so a scan that opened nothing "+
			"reads the same as a scan that found nothing:\n%s", out)
	}
}

func TestTheSummaryCountsEachRiskClassItClaimsTo(t *testing.T) {
	res := &scan.Result{
		Root:        "/src",
		FilesWalked: 4,
		Findings: []model.Finding{
			finding("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh, "a.go", 1),
			finding("ECDSA", 256, model.RiskQuantumVulnerable, model.SeverityHigh, "b.go", 2),
			finding("MD5", 0, model.RiskWeak, model.SeverityMedium, "c.go", 3),
			finding("TLS", 0, model.RiskMisconfig, model.SeverityHigh, "d.go", 4),
			finding("RSA", 4096, model.RiskExpired, model.SeverityCritical, "e.go", 5),
			finding("Ed25519", 256, model.RiskHardcoded, model.SeverityCritical, "f.go", 6),
		},
	}
	var buf bytes.Buffer
	Human(&buf, res)
	out := buf.String()

	// Each class named with the count it should carry. A class silently
	// dropped from the map still prints as a zero, and a zero here is the
	// answer everybody wants to see.
	for _, want := range []string{
		"2 quantum-vulnerable", "1 weak", "1 misconfig", "1 expired", "1 hardcoded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the summary does not say %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "RSA-2048") {
		t.Fatalf("a key size is missing from the algorithm column, and RSA "+
			"without its size is not a verdict:\n%s", out)
	}
}

// Occurrences collapse into one row per asset, and the row says how many. An
// asset in thirty files rendered as one line with no count reads as one
// problem in one place.
func TestOneRowPerAssetSaysHowManyPlacesItIsIn(t *testing.T) {
	res := &scan.Result{
		Root:        "/src",
		FilesWalked: 3,
		Findings: []model.Finding{
			finding("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh, "a.go", 1),
			finding("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh, "b.go", 2),
			finding("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh, "c.go", 3),
		},
	}
	var buf bytes.Buffer
	Human(&buf, res)
	out := buf.String()

	if !strings.Contains(out, "1 unique assets") {
		t.Fatalf("three findings of one asset did not collapse to one:\n%s", out)
	}
	if !strings.Contains(out, "+2 more") {
		t.Fatalf("the row does not say the asset is in two more places, so it "+
			"reads as one problem in one file:\n%s", out)
	}
}

func TestWhereRendersAPlaceAndSaysWhatItIsNotShowing(t *testing.T) {
	res := &scan.Result{Findings: []model.Finding{
		finding("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh, "only.go", 0),
	}}
	var buf bytes.Buffer
	Human(&buf, res)
	out := buf.String()

	if !strings.Contains(out, "only.go") {
		t.Fatalf("the file is missing from the WHERE column:\n%s", out)
	}
	// Line 0 means "not line-specific", so no bare ":0" should appear.
	if strings.Contains(out, "only.go:0") {
		t.Fatalf("a finding with no line rendered as line zero, which points "+
			"at a place that does not exist:\n%s", out)
	}
	if strings.Contains(out, "more") {
		t.Fatalf("a single occurrence claimed there were others:\n%s", out)
	}
}
