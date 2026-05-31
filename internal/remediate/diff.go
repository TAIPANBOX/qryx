package remediate

import (
	"fmt"
	"strings"
)

// diffContext is how many unchanged lines surround a change in a hunk.
const diffContext = 3

// unifiedDiff renders a unified diff between oldS and newS for one file. Our
// rules replace tokens in place and preserve line count, so when the line
// counts match we emit minimal hunks around the changed lines; if they ever
// differ we fall back to a single whole-file hunk.
func unifiedDiff(file, oldS, newS string) string {
	oldLines := strings.Split(oldS, "\n")
	newLines := strings.Split(newS, "\n")

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", file)
	fmt.Fprintf(&b, "+++ b/%s\n", file)

	if len(oldLines) != len(newLines) {
		fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
		for _, l := range oldLines {
			fmt.Fprintf(&b, "-%s\n", l)
		}
		for _, l := range newLines {
			fmt.Fprintf(&b, "+%s\n", l)
		}
		return b.String()
	}

	changed := map[int]bool{}
	var idx []int
	for i := range oldLines {
		if oldLines[i] != newLines[i] {
			changed[i] = true
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return ""
	}

	for _, h := range hunks(idx, len(oldLines)) {
		count := h.end - h.start + 1
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", h.start+1, count, h.start+1, count)
		for i := h.start; i <= h.end; i++ {
			if changed[i] {
				fmt.Fprintf(&b, "-%s\n", oldLines[i])
				fmt.Fprintf(&b, "+%s\n", newLines[i])
			} else {
				fmt.Fprintf(&b, " %s\n", oldLines[i])
			}
		}
	}
	return b.String()
}

type hunk struct{ start, end int }

// hunks groups changed line indices into hunks, padding each by diffContext and
// merging neighbours that touch or overlap.
func hunks(changed []int, n int) []hunk {
	var out []hunk
	for _, c := range changed {
		s := max(c-diffContext, 0)
		e := min(c+diffContext, n-1)
		if len(out) > 0 && s <= out[len(out)-1].end+1 {
			if e > out[len(out)-1].end {
				out[len(out)-1].end = e
			}
			continue
		}
		out = append(out, hunk{s, e})
	}
	return out
}
