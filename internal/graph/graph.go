// Package graph aggregates flat findings into a cryptographic asset graph: one
// node per logical asset, carrying every place it occurs across all sources.
// This is what turns qryx output from a list of hits into a deduplicated CBOM
// graph.
package graph

import (
	"sort"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// Occurrence is one place an asset was observed.
type Occurrence struct {
	Location  model.Location
	Primitive model.Primitive
	Source    string
	Evidence  string
}

// AssetNode is a unique cryptographic asset with all of its occurrences and the
// highest-severity risk observed across them.
type AssetNode struct {
	Asset       model.Asset
	Risk        model.Risk
	Occurrences []Occurrence
}

// key identifies a logical asset: an algorithm of a given size and kind,
// regardless of where or how often it appears.
type key struct {
	typ     model.AssetType
	algo    string // normalized
	keySize int
}

func keyOf(a model.Asset) key {
	return key{typ: a.Type, algo: risk.NormalizeAlgorithm(a.Algorithm), keySize: a.KeySize}
}

// Build groups findings into asset nodes, deduplicating identical occurrences
// and keeping the highest-severity risk per asset. The result is sorted by
// severity (desc), then algorithm, then key size for stable output.
func Build(findings []model.Finding) []AssetNode {
	nodes := map[key]*AssetNode{}
	seen := map[key]map[Occurrence]bool{}
	var order []key

	for _, f := range findings {
		k := keyOf(f.Asset)
		node, ok := nodes[k]
		if !ok {
			node = &AssetNode{Asset: f.Asset, Risk: f.Risk}
			nodes[k] = node
			seen[k] = map[Occurrence]bool{}
			order = append(order, k)
		} else if f.Risk.Severity > node.Risk.Severity {
			node.Risk = f.Risk
		}

		occ := Occurrence{
			Location:  f.Location,
			Primitive: f.Asset.Primitive,
			Source:    f.Source,
			Evidence:  f.Evidence,
		}
		if !seen[k][occ] {
			seen[k][occ] = true
			node.Occurrences = append(node.Occurrences, occ)
		}
	}

	out := make([]AssetNode, 0, len(order))
	for _, k := range order {
		out = append(out, *nodes[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk.Severity != out[j].Risk.Severity {
			return out[i].Risk.Severity > out[j].Risk.Severity
		}
		if out[i].Asset.Algorithm != out[j].Asset.Algorithm {
			return out[i].Asset.Algorithm < out[j].Asset.Algorithm
		}
		return out[i].Asset.KeySize < out[j].Asset.KeySize
	})
	return out
}
