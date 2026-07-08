// Package report renders scan results as CBOM and human-readable output.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Human writes a prioritized, human-readable summary of the scan, one row per
// unique cryptographic asset with its occurrence count.
func Human(w io.Writer, res *scan.Result) {
	nodes := graph.Build(res.Findings)

	counts := map[model.RiskClass]int{}
	for _, n := range nodes {
		if n.Risk.Class != model.RiskNone && n.Risk.Class != "" {
			counts[n.Risk.Class]++
		}
	}

	fmt.Fprintf(w, "qryx scan: %s\n", res.Root)
	fmt.Fprintf(w, "%d sources scanned, %d findings, %d unique assets\n\n",
		res.FilesWalked, len(res.Findings), len(nodes))

	if len(nodes) == 0 {
		fmt.Fprintln(w, "No cryptographic assets detected.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRISK\tALGORITHM\tOCCURRENCES\tWHERE\tDETAIL")
	for _, n := range nodes {
		algo := n.Asset.Algorithm
		if n.Asset.KeySize > 0 {
			algo = fmt.Sprintf("%s-%d", algo, n.Asset.KeySize)
		}
		risk := string(n.Risk.Class)
		if risk == "" {
			risk = string(model.RiskNone)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			n.Risk.Severity, risk, algo, len(n.Occurrences), where(n), n.Risk.Reason)
	}
	_ = tw.Flush()

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d quantum-vulnerable, %d weak, %d misconfig, %d expired, %d hardcoded (unique assets)\n",
		counts[model.RiskQuantumVulnerable], counts[model.RiskWeak],
		counts[model.RiskMisconfig], counts[model.RiskExpired], counts[model.RiskHardcoded])
}

// where renders a representative location for an asset node: the first
// occurrence, with a "(+N more)" suffix when there are others.
func where(n graph.AssetNode) string {
	if len(n.Occurrences) == 0 {
		return ""
	}
	loc := n.Occurrences[0].Location.File
	if n.Occurrences[0].Location.Line > 0 {
		loc = fmt.Sprintf("%s:%d", loc, n.Occurrences[0].Location.Line)
	}
	if extra := len(n.Occurrences) - 1; extra > 0 {
		loc = fmt.Sprintf("%s (+%d more)", loc, extra)
	}
	return loc
}
