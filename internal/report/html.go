package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

//go:embed report.tmpl.html
var htmlTemplateSrc string

// htmlTemplate is parsed once. html/template auto-escapes every field, so
// untrusted file paths and evidence cannot inject markup.
var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateSrc))

// htmlView is the logic-light model handed to the template.
type htmlView struct {
	Root     string
	Sources  int
	Findings int
	Assets   int
	Chips    []htmlChip
	Rows     []htmlRow
}

type htmlChip struct {
	Class string
	Count int
	Sev   string
}

type htmlRow struct {
	Sev       string
	Class     string
	Algo      string
	Count     int
	Reason    string
	First     string
	More      int
	Locations []string
}

// HTML renders the asset graph as a self-contained HTML page.
func HTML(w io.Writer, res *scan.Result) error {
	nodes := graph.Build(res.Findings)

	// Worst severity seen per risk class, for chip coloring.
	worst := map[model.RiskClass]model.Severity{}
	counts := map[model.RiskClass]int{}
	for _, n := range nodes {
		if n.Risk.Class == model.RiskNone || n.Risk.Class == "" {
			continue
		}
		counts[n.Risk.Class]++
		if n.Risk.Severity > worst[n.Risk.Class] {
			worst[n.Risk.Class] = n.Risk.Severity
		}
	}

	view := htmlView{
		Root:     res.Root,
		Sources:  res.FilesWalked,
		Findings: len(res.Findings),
		Assets:   len(nodes),
	}
	for _, c := range []model.RiskClass{model.RiskQuantumVulnerable, model.RiskWeak, model.RiskMisconfig, model.RiskExpired, model.RiskHardcoded} {
		if counts[c] > 0 {
			view.Chips = append(view.Chips, htmlChip{Class: string(c), Count: counts[c], Sev: worst[c].String()})
		}
	}
	for _, n := range nodes {
		view.Rows = append(view.Rows, rowOf(n))
	}

	return htmlTemplate.Execute(w, view)
}

func rowOf(n graph.AssetNode) htmlRow {
	locs := make([]string, 0, len(n.Occurrences))
	for _, o := range n.Occurrences {
		loc := o.Location.File
		if o.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, o.Location.Line)
		}
		if o.Source != "" {
			loc += "  [" + o.Source + "]"
		}
		locs = append(locs, loc)
	}
	first := ""
	if len(locs) > 0 {
		first = locs[0]
	}
	class := string(n.Risk.Class)
	if class == "" {
		class = string(model.RiskNone)
	}
	return htmlRow{
		Sev:       n.Risk.Severity.String(),
		Class:     class,
		Algo:      assetName(n),
		Count:     len(n.Occurrences),
		Reason:    n.Risk.Reason,
		First:     first,
		More:      len(locs) - 1,
		Locations: locs,
	}
}
