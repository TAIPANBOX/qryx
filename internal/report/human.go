// Package report renders scan results as CBOM and human-readable output.
package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Human writes a prioritized, human-readable summary of the scan.
func Human(w io.Writer, res *scan.Result) {
	findings := append([]model.Finding(nil), res.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Risk.Severity != findings[j].Risk.Severity {
			return findings[i].Risk.Severity > findings[j].Risk.Severity
		}
		return findings[i].Location.File < findings[j].Location.File
	})

	counts := map[model.RiskClass]int{}
	for _, f := range findings {
		if f.Risk.Class != model.RiskNone && f.Risk.Class != "" {
			counts[f.Risk.Class]++
		}
	}

	fmt.Fprintf(w, "qryx scan: %s\n", res.Root)
	fmt.Fprintf(w, "%d files scanned, %d findings\n\n", res.FilesWalked, len(findings))

	if len(findings) == 0 {
		fmt.Fprintln(w, "No cryptographic assets detected.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRISK\tALGORITHM\tLOCATION\tDETAIL")
	for _, f := range findings {
		loc := f.Location.File
		if f.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Line)
		}
		algo := f.Asset.Algorithm
		if f.Asset.KeySize > 0 {
			algo = fmt.Sprintf("%s-%d", algo, f.Asset.KeySize)
		}
		risk := string(f.Risk.Class)
		if risk == "" {
			risk = string(model.RiskNone)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.Risk.Severity, risk, algo, loc, f.Risk.Reason)
	}
	tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d quantum-vulnerable, %d weak, %d misconfig, %d expired, %d hardcoded\n",
		counts[model.RiskQuantumVulnerable], counts[model.RiskWeak],
		counts[model.RiskMisconfig], counts[model.RiskExpired], counts[model.RiskHardcoded])
}
