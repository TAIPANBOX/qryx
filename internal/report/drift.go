package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/store"
)

// Drift writes the change in the asset graph relative to a baseline snapshot.
func Drift(w io.Writer, d store.Delta) {
	if d.Empty() {
		fmt.Fprintln(w, "\nDrift vs baseline: none")
		return
	}

	fmt.Fprintf(w, "\nDrift vs baseline: +%d new, -%d removed\n", len(d.Added), len(d.Removed))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, n := range d.Added {
		fmt.Fprintf(tw, "  NEW\t%s\t%s\t%s\n", n.Risk.Severity, assetName(n), where(n))
	}
	for _, n := range d.Removed {
		fmt.Fprintf(tw, "  REMOVED\t%s\t%s\t%s\n", n.Risk.Severity, assetName(n), where(n))
	}
	tw.Flush()
}

// assetName renders an asset's algorithm with its key size when known.
func assetName(n graph.AssetNode) string {
	if n.Asset.KeySize > 0 {
		return fmt.Sprintf("%s-%d", n.Asset.Algorithm, n.Asset.KeySize)
	}
	return n.Asset.Algorithm
}
