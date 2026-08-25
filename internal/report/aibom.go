package report

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

// AIInventorySchema names the document this reporter writes. A consumer reads
// it before anything else and refuses a version it does not know, so the shape
// can grow without a reader guessing which one it is holding.
const AIInventorySchema = "qryx.ai-inventory/v1"

// The AI-usage findings are excluded from every other machine format this tool
// writes, and each exclusion is right: a CBOM is a Cryptography Bill of
// Materials, and the CNSA and NCSC reports are compliance verdicts about
// cryptographic posture. An inventory fact riding in any of them would be
// mislabelled as a cryptographic one. That left the code-side AI inventory
// reachable only through the human table and the HTML page, both of which are
// read by a person and neither of which another program can consume. This
// document is the door out.
//
// It is deliberately not CycloneDX. The findings here are "this source tree
// mentions this provider", which is weaker than any component claim that
// format's AI extensions are built to carry, and dressing the evidence up in a
// standard's vocabulary would overstate what a regex over source text knows.
//
// # WHAT A CONSUMER JOINS ON
//
// The provider id, not the label. The label is prose for a person; the id is
// the join key, and it comes from the detector's own tables rather than being
// re-derived here, so there is one row per provider in the whole tool. An
// empty provider on a framework row is a fact and not a gap: see roleFramework
// in the detector.
type aiInventoryDoc struct {
	Schema      string           `json:"schema"`
	Tool        aiTool           `json:"tool"`
	GeneratedAt string           `json:"generatedAt"`
	Root        string           `json:"root"`
	FilesWalked int              `json:"filesWalked"`
	Entries     []aiInventoryRow `json:"entries"`
	Limits      []string         `json:"limits"`
}

type aiTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type aiInventoryRow struct {
	Provider    string                  `json:"provider"`
	Role        string                  `json:"role"`
	Label       string                  `json:"label"`
	Occurrences []aiInventoryOccurrence `json:"occurrences"`
}

type aiInventoryOccurrence struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// AIInventory writes the AI-usage half of a scan as JSON to w.
//
// Limits are carried in the document rather than left to a reader's optimism,
// because the one thing this inventory must never be read as is proof of
// absence: a tree that builds its endpoint at runtime, or reaches a model
// through an indirection the text does not name, produces no entry here and is
// no less real for it. That is invariant 6 written into the artifact instead of
// into a doc comment nobody downstream will read.
func AIInventory(w io.Writer, res *scan.Result, version string) error {
	doc := aiInventoryDoc{
		Schema:      AIInventorySchema,
		Tool:        aiTool{Name: "qryx", Version: version},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        res.Root,
		FilesWalked: res.FilesWalked,
		Entries:     []aiInventoryRow{},
		Limits:      detectors.AIUsageLimits,
	}

	for _, node := range graph.Build(res.Findings) {
		if node.Asset.Type != model.TypeAIModel {
			continue
		}
		doc.Entries = append(doc.Entries, toInventoryRow(node))
	}

	// Sorted rather than left in graph order, so two scans of one tree produce
	// one document and a consumer diffing them sees a real change or nothing.
	sort.Slice(doc.Entries, func(i, j int) bool {
		a, b := doc.Entries[i], doc.Entries[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Label < b.Label
	})

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// toInventoryRow renders one asset node with every occurrence of it: the
// graph, not a flat per-finding dump, which is what invariant 2 requires and
// what keeps the counts here agreeing with the counts everywhere else.
func toInventoryRow(n graph.AssetNode) aiInventoryRow {
	row := aiInventoryRow{
		Provider:    n.Tags["qryx.ai.provider"],
		Role:        n.Tags["qryx.ai.role"],
		Label:       n.Asset.Algorithm,
		Occurrences: []aiInventoryOccurrence{},
	}
	for _, occ := range n.Occurrences {
		row.Occurrences = append(row.Occurrences, aiInventoryOccurrence{
			File:     occ.Location.File,
			Line:     occ.Location.Line,
			Evidence: occ.Evidence,
		})
	}
	sort.Slice(row.Occurrences, func(i, j int) bool {
		a, b := row.Occurrences[i], row.Occurrences[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return row
}
