package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"text/tabwriter"

	"github.com/TAIPANBOX/qryx/internal/store"
)

//go:embed trend.tmpl.html
var trendTemplateSrc string

var trendTemplate = template.Must(template.New("trend").Parse(trendTemplateSrc))

// Trend writes the compliance-score history from an evidence trail, with a
// delta line on the latest change so regressions are obvious.
//
// The not-assessed column is there because the score alone does not say what it
// is a percentage of. Two runs can both read 50% while one graded its whole
// inventory and the other graded half of it, and a delta between those two is
// not a change in posture at all.
func Trend(w io.Writer, records []store.EvidenceRecord) {
	if len(records) == 0 {
		fmt.Fprintln(w, "Evidence trail: empty")
		return
	}

	fmt.Fprintf(w, "Evidence trail: %d record(s)\n", len(records))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  DATE\tSCORE\tNON-COMPLIANT\tNOT-ASSESSED\tDIGEST")
	for _, r := range records {
		fmt.Fprintf(tw, "  %s\t%d%%\t%d\t%d\t%s\n",
			r.CreatedAt.UTC().Format("2006-01-02 15:04"), r.ScorePct,
			r.NonCompliant, r.NotAssessed, shortDigest(r.Digest))
	}
	_ = tw.Flush()

	if note := notAssessedNote(records[len(records)-1]); note != "" {
		fmt.Fprintln(w, note)
	}
	if len(records) >= 2 {
		prev, cur := records[len(records)-2], records[len(records)-1]
		fmt.Fprintln(w, scoreDelta(prev.ScorePct, cur.ScorePct))
	}
}

// notAssessedNote states the ungraded share of the latest scan against the
// inventory it came from, or nothing at all when everything was graded. A
// caveat printed on every clean run is a caveat nobody reads on the run where
// it matters, so silence here is the point rather than an omission.
func notAssessedNote(r store.EvidenceRecord) string {
	if r.NotAssessed <= 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d assets were not assessed against CNSA 2.0 and count "+
		"in the score's denominator; grade them by hand before reading the score as posture.",
		r.NotAssessed, r.Total)
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

// trendHTMLView is the chart template model.
type trendHTMLView struct {
	Count           int
	Polyline        string       // SVG points "x,y x,y ..."
	Points          []trendPoint // markers + labels
	Latest          int          // latest score
	DeltaText       string       // delta description
	DeltaClass      string       // up | down | flat (for styling)
	NotAssessedNote string       // ungraded share of the latest scan, empty when none
}

type trendPoint struct {
	X, Y        int
	Score       int
	Date        string
	NotAssessed int
}

// chart geometry
const (
	chartW, chartH = 720, 240
	padX, padTop   = 40, 20
	padBottom      = 40
)

// TrendHTML renders a self-contained HTML page with an SVG line chart of the
// compliance score over time.
func TrendHTML(w io.Writer, records []store.EvidenceRecord) error {
	v := trendHTMLView{Count: len(records)}

	plotW := chartW - 2*padX
	plotH := chartH - padTop - padBottom
	step := 0
	if len(records) > 1 {
		step = plotW / (len(records) - 1)
	}
	for i, r := range records {
		x := padX + i*step
		if len(records) == 1 {
			x = chartW / 2
		}
		y := padTop + (plotH - r.ScorePct*plotH/100)
		v.Points = append(v.Points, trendPoint{
			X: x, Y: y, Score: r.ScorePct,
			Date:        r.CreatedAt.UTC().Format("2006-01-02"),
			NotAssessed: r.NotAssessed,
		})
		if v.Polyline != "" {
			v.Polyline += " "
		}
		v.Polyline += fmt.Sprintf("%d,%d", x, y)
	}
	if len(records) > 0 {
		v.Latest = records[len(records)-1].ScorePct
		v.NotAssessedNote = notAssessedNote(records[len(records)-1])
	}
	if len(records) >= 2 {
		prev, cur := records[len(records)-2].ScorePct, records[len(records)-1].ScorePct
		v.DeltaText = scoreDelta(prev, cur)
		switch {
		case cur > prev:
			v.DeltaClass = "up"
		case cur < prev:
			v.DeltaClass = "down"
		default:
			v.DeltaClass = "flat"
		}
	}
	return trendTemplate.Execute(w, v)
}

func shortDigest(d string) string {
	const prefix = "sha256:"
	if len(d) > len(prefix)+12 {
		return d[:len(prefix)+12]
	}
	return d
}
