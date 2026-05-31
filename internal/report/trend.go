package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/store"
)

// Trend writes the compliance-score history from an evidence trail, with a
// delta line on the latest change so regressions are obvious.
func Trend(w io.Writer, records []store.EvidenceRecord) {
	if len(records) == 0 {
		fmt.Fprintln(w, "Evidence trail: empty")
		return
	}

	fmt.Fprintf(w, "Evidence trail: %d record(s)\n", len(records))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  DATE\tSCORE\tNON-COMPLIANT\tDIGEST")
	for _, r := range records {
		fmt.Fprintf(tw, "  %s\t%d%%\t%d\t%s\n",
			r.CreatedAt.UTC().Format("2006-01-02 15:04"), r.ScorePct, r.NonCompliant, shortDigest(r.Digest))
	}
	tw.Flush()

	if len(records) >= 2 {
		prev, cur := records[len(records)-2], records[len(records)-1]
		fmt.Fprintln(w, scoreDelta(prev.ScorePct, cur.ScorePct))
	}
}

func scoreDelta(prev, cur int) string {
	switch {
	case cur > prev:
		return fmt.Sprintf("Score improved +%d (%d%% -> %d%%)", cur-prev, prev, cur)
	case cur < prev:
		return fmt.Sprintf("Score regressed -%d (%d%% -> %d%%)", prev-cur, prev, cur)
	default:
		return fmt.Sprintf("Score unchanged (%d%%)", cur)
	}
}

func shortDigest(d string) string {
	const prefix = "sha256:"
	if len(d) > len(prefix)+12 {
		return d[:len(prefix)+12]
	}
	return d
}
