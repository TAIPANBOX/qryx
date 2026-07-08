package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/policy"
)

// Violations writes a concise human report of policy violations. It mirrors
// Drift: one line per violation with severity, rule, asset and where it occurs.
func Violations(w io.Writer, name string, vs []policy.Violation) {
	if len(vs) == 0 {
		fmt.Fprintf(w, "\nPolicy %q: PASS (no violations)\n", name)
		return
	}
	fmt.Fprintf(w, "\nPolicy %q: FAIL (%d violation(s))\n", name, len(vs))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, v := range vs {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", v.Severity, v.Rule, v.Asset, firstLocation(v), v.Message)
	}
	_ = tw.Flush()
}

func firstLocation(v policy.Violation) string {
	if len(v.Locations) == 0 {
		return ""
	}
	if extra := len(v.Locations) - 1; extra > 0 {
		return fmt.Sprintf("%s (+%d)", v.Locations[0], extra)
	}
	return v.Locations[0]
}
