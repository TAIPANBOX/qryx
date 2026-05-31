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

// trendHTMLView is the chart template model.
type trendHTMLView struct {
	Count      int
	Polyline   string       // SVG points "x,y x,y ..."
	Points     []trendPoint // markers + labels
	Latest     int          // latest score
	DeltaText  string       // delta description
	DeltaClass string       // up | down | flat (for styling)
}

type trendPoint struct {
	X, Y  int
	Score int
	Date  string
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
		v.Points = append(v.Points, trendPoint{X: x, Y: y, Score: r.ScorePct, Date: r.CreatedAt.UTC().Format("2006-01-02")})
		if v.Polyline != "" {
			v.Polyline += " "
		}
		v.Polyline += fmt.Sprintf("%d,%d", x, y)
	}
	if len(records) > 0 {
		v.Latest = records[len(records)-1].ScorePct
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
