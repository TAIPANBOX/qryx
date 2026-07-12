package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

//go:embed cnsa.tmpl.html
var cnsaTemplateSrc string

var cnsaTemplate = template.Must(
	template.New("cnsa").Funcs(template.FuncMap{
		"assetNameFn": assetName,
		"firstLoc": func(n graph.AssetNode) string {
			if len(n.Occurrences) == 0 {
				return ""
			}
			o := n.Occurrences[0]
			if o.Location.Line > 0 {
				return fmt.Sprintf("%s:%d", o.Location.File, o.Location.Line)
			}
			return o.Location.File
		},
		"extraCount": func(n graph.AssetNode) int {
			if len(n.Occurrences) <= 1 {
				return 0
			}
			return len(n.Occurrences) - 1
		},
		"locStr": func(o graph.Occurrence) string {
			if o.Location.Line > 0 {
				return fmt.Sprintf("%s:%d", o.Location.File, o.Location.Line)
			}
			return o.Location.File
		},
		"deadlineClass": func(d string) string {
			switch d {
			case "immediate":
				return "dl-im"
			case "2027":
				return "dl-27"
			case "2030":
				return "dl-30"
			default:
				return ""
			}
		},
	}).Parse(cnsaTemplateSrc),
)

// cnsaEntry is one asset's CNSA 2.0 compliance record.
type cnsaEntry struct {
	Node     graph.AssetNode
	Status   string // "compliant" | "non-compliant" | "issue"
	Deadline string // "2027" | "2030" | "2035" | "immediate" | "n/a"
	Action   string
}

// cnsaStatus classifies an asset node against the CNSA 2.0 standard.
func cnsaStatus(n graph.AssetNode) cnsaEntry {
	// Context issues (not algorithm-specific) are evaluated first: a real
	// context risk must always win over algorithm compliance. Otherwise an
	// asset whose algorithm is otherwise CNSA-approved (e.g. AES, ML-KEM)
	// would short-circuit to "compliant" before its expiry/hardcoding/
	// misconfiguration was ever consulted.
	switch n.Risk.Class {
	case model.RiskExpired:
		return cnsaEntry{Node: n, Status: "issue", Deadline: "immediate",
			Action: "Certificate is expired; renew immediately."}
	case model.RiskHardcoded:
		return cnsaEntry{Node: n, Status: "issue", Deadline: "immediate",
			Action: "Private key material in source/config; rotate and remove."}
	case model.RiskMisconfig:
		return cnsaEntry{Node: n, Status: "issue", Deadline: "immediate",
			Action: "TLS misconfiguration; enforce TLS 1.3 per CNSA 2.0."}
	}

	// Quantum-vulnerable: must migrate per CNSA 2.0 schedule.
	if n.Risk.Class == model.RiskQuantumVulnerable {
		action := quantumAction(n.Asset.Algorithm)
		return cnsaEntry{Node: n, Status: "non-compliant", Deadline: "2030", Action: action}
	}

	// Classically weak: already non-compliant regardless of quantum timeline.
	if n.Risk.Class == model.RiskWeak {
		return cnsaEntry{Node: n, Status: "non-compliant", Deadline: "immediate",
			Action: fmt.Sprintf("%s is not approved by CNSA 2.0; replace immediately.", n.Asset.Algorithm)}
	}

	// No context risk (Risk.Class == RiskNone): grade on algorithm+size alone.
	algo := strings.ToUpper(strings.ReplaceAll(n.Asset.Algorithm, "-", ""))

	// Post-quantum safe (FIPS 203/204/205) and approved symmetric/hash.
	switch algo {
	case "MLKEM", "MLDSA", "SLHDSA":
		return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
			Action: "Approved CNSA 2.0 post-quantum algorithm."}
	case "AES":
		if n.Asset.KeySize == 0 || n.Asset.KeySize >= 256 {
			return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
				Action: "AES-256 is the CNSA 2.0 approved symmetric cipher."}
		}
		return cnsaEntry{Node: n, Status: "non-compliant", Deadline: "immediate",
			Action: fmt.Sprintf("AES-%d is below the CNSA 2.0 minimum of 256 bits. Upgrade to AES-256.", n.Asset.KeySize)}
	case "SHA384", "SHA512":
		return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
			Action: "SHA-384/512 is the CNSA 2.0 approved hash function."}
	}

	// Unknown / RiskNone — include as informational.
	return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
		Action: "No CNSA 2.0 restriction identified."}
}

func quantumAction(algo string) string {
	switch strings.ToUpper(algo) {
	case "RSA":
		return "Migrate to ML-KEM (key encapsulation) or ML-DSA (signatures) per CNSA 2.0 §3.1."
	case "ECDSA", "ECC", "DSA":
		return "Migrate to ML-DSA (FIPS 204) for digital signatures per CNSA 2.0 §3.2."
	case "ECDH", "DH":
		return "Migrate to ML-KEM (FIPS 203) for key exchange per CNSA 2.0 §3.1."
	default:
		return fmt.Sprintf("%s is quantum-vulnerable; migrate to CNSA 2.0 approved algorithms.", algo)
	}
}

// deadlineOrder gives a sort key so urgent items sort first.
var deadlineOrder = map[string]int{
	"immediate": 0,
	"2027":      1,
	"2030":      2,
	"2035":      3,
	"n/a":       4,
}

// cnsaReport is the JSON output schema.
type cnsaReport struct {
	Standard    string          `json:"standard"`
	GeneratedAt string          `json:"generatedAt"`
	Root        string          `json:"root"`
	Summary     cnsaSummary     `json:"summary"`
	Assets      []cnsaAssetJSON `json:"assets"`
}

type cnsaSummary struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"nonCompliant"`
	Issues       int `json:"issues"`
	Total        int `json:"total"`
}

type cnsaAssetJSON struct {
	Algorithm   string            `json:"algorithm"`
	Type        string            `json:"type"`
	Status      string            `json:"status"`
	Deadline    string            `json:"deadline"`
	Action      string            `json:"action"`
	Occurrences int               `json:"occurrences"`
	Locations   []string          `json:"locations,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// CNSA writes a machine-readable CNSA 2.0 audit report as JSON.
func CNSA(w io.Writer, res *scan.Result) error {
	entries := buildEntries(res)
	rep := cnsaReport{
		Standard:    "CNSA 2.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        res.Root,
	}
	for _, e := range entries {
		switch e.Status {
		case "compliant":
			rep.Summary.Compliant++
		case "non-compliant":
			rep.Summary.NonCompliant++
		case "issue":
			rep.Summary.Issues++
		}
		rep.Summary.Total++

		locs := make([]string, 0, len(e.Node.Occurrences))
		for _, o := range e.Node.Occurrences {
			loc := o.Location.File
			if o.Location.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, o.Location.Line)
			}
			locs = append(locs, loc)
		}
		rep.Assets = append(rep.Assets, cnsaAssetJSON{
			Algorithm:   assetName(e.Node),
			Type:        string(e.Node.Asset.Type),
			Status:      e.Status,
			Deadline:    e.Deadline,
			Action:      e.Action,
			Occurrences: len(e.Node.Occurrences),
			Locations:   locs,
			Tags:        e.Node.Tags,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// buildEntries classifies all graph nodes and sorts by deadline urgency then
// occurrence count (descending).
func buildEntries(res *scan.Result) []cnsaEntry {
	nodes := graph.Build(res.Findings)
	entries := make([]cnsaEntry, len(nodes))
	for i, n := range nodes {
		entries[i] = cnsaStatus(n)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		di, dj := deadlineOrder[entries[i].Deadline], deadlineOrder[entries[j].Deadline]
		if di != dj {
			return di < dj
		}
		return len(entries[i].Node.Occurrences) > len(entries[j].Node.Occurrences)
	})
	return entries
}

// cnsaHTMLView is the template data model.
type cnsaHTMLView struct {
	Root              string
	GeneratedAt       string
	ScorePct          int
	Summary           cnsaSummary
	NonCompliant      []cnsaEntry
	Issues            []cnsaEntry
	Compliant         []cnsaEntry
	ImmediateCount    int
	Deadline2027Count int
	Deadline2030Count int
}

// CNSAHTML renders a self-contained CNSA 2.0 HTML audit report.
func CNSAHTML(w io.Writer, res *scan.Result) error {
	entries := buildEntries(res)
	v := cnsaHTMLView{
		Root:        res.Root,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	}
	for _, e := range entries {
		switch e.Status {
		case "compliant":
			v.Summary.Compliant++
			v.Compliant = append(v.Compliant, e)
		case "non-compliant":
			v.Summary.NonCompliant++
			v.NonCompliant = append(v.NonCompliant, e)
			switch e.Deadline {
			case "immediate":
				v.ImmediateCount++
			case "2027":
				v.Deadline2027Count++
			case "2030":
				v.Deadline2030Count++
			}
		case "issue":
			v.Summary.Issues++
			v.Issues = append(v.Issues, e)
			v.ImmediateCount++
		}
	}
	v.Summary.Total = v.Summary.Compliant + v.Summary.NonCompliant + v.Summary.Issues
	if v.Summary.Total > 0 {
		v.ScorePct = v.Summary.Compliant * 100 / v.Summary.Total
	}
	return cnsaTemplate.Execute(w, v)
}
