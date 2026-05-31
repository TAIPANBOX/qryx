package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/TAIPANBOX/qryx/internal/scan"
)

//go:embed dashboard.tmpl.html
var dashboardTemplateSrc string

var dashboardTemplate = template.Must(
	template.New("dashboard").Funcs(template.FuncMap{
		"assetNameFn": assetName,
		"dashWhere":   dashWhere,
	}).Parse(dashboardTemplateSrc),
)

// dashboardMaxPriorities caps the remediation list shown on the dashboard.
const dashboardMaxPriorities = 8

type dashboardView struct {
	Root         string
	GeneratedAt  string
	Version      string
	Digest       string
	ScorePct     int
	Summary      evidenceSummary
	BySeverity   []severityCount
	Priorities   []priorityRow
	NonCompliant []cnsaEntry
}

type severityCount struct {
	Severity string
	Count    int
}

type priorityRow struct {
	Rank        int
	Algorithm   string
	Target      string
	Agility     string
	Severity    string
	Occurrences int
}

// severityOrder lists severities high-to-low for a deterministic profile.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// Dashboard renders a self-contained governance dashboard: compliance score,
// severity profile, evidence digest, and the top remediation priorities.
func Dashboard(w io.Writer, res *scan.Result, version string) error {
	ev, err := buildEvidence(res, version)
	if err != nil {
		return err
	}

	v := dashboardView{
		Root:        res.Root,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Version:     version,
		Digest:      ev.Digest,
		ScorePct:    ev.Summary.ScorePct,
		Summary:     ev.Summary,
	}
	for _, s := range severityOrder {
		if c := ev.Summary.BySeverity[s]; c > 0 {
			v.BySeverity = append(v.BySeverity, severityCount{Severity: s, Count: c})
		}
	}

	steps := rankedSteps(res)
	for i, s := range steps {
		if i >= dashboardMaxPriorities {
			break
		}
		v.Priorities = append(v.Priorities, priorityRow{
			Rank:        i + 1,
			Algorithm:   assetName(s.node),
			Target:      s.a.Target,
			Agility:     string(s.a.Agility),
			Severity:    s.node.Risk.Severity.String(),
			Occurrences: len(s.node.Occurrences),
		})
	}

	for _, e := range buildEntries(res) {
		if e.Status == "non-compliant" {
			v.NonCompliant = append(v.NonCompliant, e)
		}
	}

	return dashboardTemplate.Execute(w, v)
}

// dashWhere renders the first location of a node for the compact tables.
func dashWhere(e cnsaEntry) string {
	if len(e.Node.Occurrences) == 0 {
		return ""
	}
	o := e.Node.Occurrences[0]
	loc := o.Location.File
	if o.Location.Line > 0 {
		loc = fmt.Sprintf("%s:%d", o.Location.File, o.Location.Line)
	}
	if extra := len(e.Node.Occurrences) - 1; extra > 0 {
		return fmt.Sprintf("%s (+%d)", loc, extra)
	}
	return loc
}
