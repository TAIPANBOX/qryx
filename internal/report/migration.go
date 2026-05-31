package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/TAIPANBOX/qryx/internal/agility"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

type migrationReport struct {
	GeneratedAt string           `json:"generatedAt"`
	Root        string           `json:"root"`
	Summary     migrationSummary `json:"summary"`
	Plan        []migrationStep  `json:"plan"`
}

type migrationSummary struct {
	ToMigrate int `json:"toMigrate"`
	QuickWins int `json:"quickWins"`
}

type migrationStep struct {
	Priority    int               `json:"priority"`
	Algorithm   string            `json:"algorithm"`
	Target      string            `json:"target"`
	Agility     string            `json:"agility"`
	Effort      string            `json:"effort"`
	Risk        string            `json:"risk"`
	Severity    string            `json:"severity"`
	Occurrences int               `json:"occurrences"`
	Rationale   string            `json:"rationale"`
	Locations   []string          `json:"locations,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// agilityRank orders agility so more-agile sorts first (quick wins).
var agilityRank = map[agility.Level]int{agility.High: 0, agility.Medium: 1, agility.Low: 2}

// Migration writes a risk-prioritized migration plan as JSON.
func Migration(w io.Writer, res *scan.Result) error {
	nodes := graph.Build(res.Findings)

	type step struct {
		node graph.AssetNode
		a    agility.Assessment
	}
	var steps []step
	for _, n := range nodes {
		a, ok := agility.Assess(n)
		if !ok {
			continue
		}
		steps = append(steps, step{n, a})
	}

	// Quick wins first: highest severity, then most agile, then most occurrences.
	sort.SliceStable(steps, func(i, j int) bool {
		si, sj := steps[i].node.Risk.Severity, steps[j].node.Risk.Severity
		if si != sj {
			return si > sj
		}
		ai, aj := agilityRank[steps[i].a.Agility], agilityRank[steps[j].a.Agility]
		if ai != aj {
			return ai < aj
		}
		return len(steps[i].node.Occurrences) > len(steps[j].node.Occurrences)
	})

	rep := migrationReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        res.Root,
	}
	for i, s := range steps {
		quickWin := s.a.Agility == agility.High &&
			(s.node.Risk.Severity == model.SeverityCritical || s.node.Risk.Severity == model.SeverityHigh)
		if quickWin {
			rep.Summary.QuickWins++
		}
		rep.Plan = append(rep.Plan, migrationStep{
			Priority:    i + 1,
			Algorithm:   assetName(s.node),
			Target:      s.a.Target,
			Agility:     string(s.a.Agility),
			Effort:      s.a.Effort,
			Risk:        string(s.node.Risk.Class),
			Severity:    s.node.Risk.Severity.String(),
			Occurrences: len(s.node.Occurrences),
			Rationale:   s.a.Rationale,
			Locations:   locations(s.node),
			Tags:        s.node.Tags,
		})
	}
	rep.Summary.ToMigrate = len(rep.Plan)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func locations(n graph.AssetNode) []string {
	out := make([]string, 0, len(n.Occurrences))
	for _, o := range n.Occurrences {
		loc := o.Location.File
		if o.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, o.Location.Line)
		}
		out = append(out, loc)
	}
	return out
}
