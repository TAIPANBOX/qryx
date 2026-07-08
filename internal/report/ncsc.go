// Package report — NCSC PQC migration readiness report.
//
// This report tracks a scan against the UK National Cyber Security Centre's
// post-quantum cryptography migration guidance, which sets three timeline
// milestones for UK-regulated organizations:
//
//   - by 2028: complete discovery — a full inventory of quantum-vulnerable
//     cryptography and a defined migration plan.
//   - by 2031: complete migration of the highest-priority systems.
//   - by 2035: complete migration of all systems.
//
// (Plain reference to NCSC PQC migration guidance; no specific document quoted
// or linked here — see the NCSC website for the source guidance.)
//
// It consumes the same cryptographic asset graph as the other reports; it does
// not re-scan or re-classify anything.
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

	"github.com/TAIPANBOX/qryx/internal/agility"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// ncscStandard is the header citation used in both the JSON and HTML reports.
const ncscStandard = "NCSC PQC migration timeline (2028/2031/2035)"

//go:embed ncsc.tmpl.html
var ncscTemplateSrc string

var ncscTemplate = template.Must(
	template.New("ncsc").Funcs(template.FuncMap{
		"ncscWhere":    ncscWhere,
		"verdictClass": verdictClass,
	}).Parse(ncscTemplateSrc),
)

// verdictClass maps a verdict to its CSS badge class.
func verdictClass(v ncscVerdict) string {
	switch v {
	case verdictOnTrack:
		return "v-ok"
	case verdictAtRisk:
		return "v-risk"
	default:
		return "v-none"
	}
}

// highestPriorityCriteria documents, in one string surfaced in both report
// formats, exactly which finding dimensions decide the 2031 "highest
// priority" subset (see isExternallyFacing / isLongLivedData below).
const highestPriorityCriteria = "quantum-vulnerable AND (externally-facing: an occurrence sourced from a live TLS probe or AWS ACM certificate; OR long-lived-data: the asset's primitive is encryption or key-exchange, i.e. subject to harvest-now-decrypt-later)"

// discoveryPlanNote documents how "migration plan artifact exists" is decided
// for the 2028 milestone: qryx does not persist a separate plan file, so this
// reuses the same agility-derived migration plan as `--format migration`
// (rankedSteps/agility.Assess). A quantum-vulnerable asset is "planned" when
// agility.Assess recognizes its algorithm and proposes a migration target;
// today that covers RSA/ECDSA/ECDH/DH/ECC/DSA/Ed25519 but not every algorithm
// risk.Classify can flag as quantum-vulnerable (e.g. SM2 is not yet mapped).
const discoveryPlanNote = "reuses the qryx migration report's plan (agility.Assess over the asset graph); an asset counts as planned when its algorithm has a recognized migration target"

// sourceBucket classifies an occurrence into one of the six discovery-coverage
// categories the milestone-1 report tracks. Container provenance is not a
// per-finding Source in qryx today — `qryx image` reuses the code (goast,
// deps, ...) and binary detectors on extracted layers — so container findings
// are identified by the scan Result's "image://" root prefix instead, checked
// by the caller before falling back to this per-source table.
var sourceBucket = map[string]string{
	"goast":      "code",
	"cryptocall": "code",
	"hardcoded":  "code",
	"deps":       "code",
	"terraform":  "code",

	"binary": "binaries",

	"tls-probe": "tls",

	"certfile": "certs",
	"aws-acm":  "certs",

	"aws-kms":        "kms",
	"gcp-kms":        "kms",
	"azure-keyvault": "kms",
}

// isImageRoot reports whether a scan Result came from `qryx image`, per the
// "image://" root prefix runImage sets in cmd/qryx/main.go.
func isImageRoot(root string) bool {
	return strings.HasPrefix(root, "image://")
}

// bucketFor classifies one occurrence's source into a discovery-coverage
// bucket for the given scan Result.
func bucketFor(root string, o graph.Occurrence) string {
	if isImageRoot(root) {
		return "containers"
	}
	if b, ok := sourceBucket[o.Source]; ok {
		return b
	}
	return "other"
}

// isExternallyFacing reports whether any occurrence of the asset was observed
// on an externally-reachable surface: a live TLS probe of a network endpoint,
// or an AWS ACM certificate (which is bound to a public-facing load balancer
// or CloudFront distribution in normal use).
func isExternallyFacing(n graph.AssetNode) bool {
	for _, o := range n.Occurrences {
		if o.Source == "tls-probe" || o.Source == "aws-acm" {
			return true
		}
	}
	return false
}

// isLongLivedData reports whether the asset protects data confidentiality
// (encryption or key-exchange) rather than authenticity (signatures) or
// integrity (hashes). Confidentiality primitives are the ones exposed to
// harvest-now-decrypt-later: data encrypted or key-exchanged today can be
// recorded and decrypted retroactively once a cryptographically relevant
// quantum computer exists, so it needs to outlive the primitive protecting it.
// Signature forgery, by contrast, is a forward-looking risk that a timely
// migration fully closes — there is nothing to "harvest" from a signature.
func isLongLivedData(n graph.AssetNode) bool {
	if n.Asset.Primitive == model.PrimitiveEncryption || n.Asset.Primitive == model.PrimitiveKeyExch {
		return true
	}
	for _, o := range n.Occurrences {
		if o.Primitive == model.PrimitiveEncryption || o.Primitive == model.PrimitiveKeyExch {
			return true
		}
	}
	return false
}

// isHighestPriority is the 2031 milestone's subset predicate: quantum
// vulnerable and (externally-facing or long-lived-data). See
// highestPriorityCriteria for the string surfaced in reports.
func isHighestPriority(n graph.AssetNode) bool {
	return n.Risk.Class == model.RiskQuantumVulnerable && (isExternallyFacing(n) || isLongLivedData(n))
}

// ncscVerdict is a milestone readiness call: "on-track", "at-risk", or
// "not-started".
type ncscVerdict string

const (
	verdictOnTrack    ncscVerdict = "on-track"
	verdictAtRisk     ncscVerdict = "at-risk"
	verdictNotStarted ncscVerdict = "not-started"
)

// ncscFindingJSON is one quantum-vulnerable asset in a milestone finding list.
type ncscFindingJSON struct {
	Algorithm        string   `json:"algorithm"`
	Type             string   `json:"type"`
	Severity         string   `json:"severity"`
	Occurrences      int      `json:"occurrences"`
	Locations        []string `json:"locations,omitempty"`
	ExternallyFacing bool     `json:"externallyFacing"`
	LongLivedData    bool     `json:"longLivedData"`
	Planned          bool     `json:"planned"`
}

func findingJSON(n graph.AssetNode, planned bool) ncscFindingJSON {
	return ncscFindingJSON{
		Algorithm:        assetName(n),
		Type:             string(n.Asset.Type),
		Severity:         n.Risk.Severity.String(),
		Occurrences:      len(n.Occurrences),
		Locations:        locations(n),
		ExternallyFacing: isExternallyFacing(n),
		LongLivedData:    isLongLivedData(n),
		Planned:          planned,
	}
}

// ncscDiscovery is the 2028 "complete discovery" milestone.
type ncscDiscovery struct {
	Verdict           ncscVerdict       `json:"verdict"`
	CoverageBySource  map[string]int    `json:"coverageBySource"`
	TotalInventoried  int               `json:"totalInventoried"`
	QuantumVulnerable int               `json:"quantumVulnerableCount"`
	PlanExists        bool              `json:"migrationPlanExists"`
	PlanNote          string            `json:"migrationPlanNote"`
	Findings          []ncscFindingJSON `json:"quantumVulnerableFindings"`
}

// ncscHighestPriority is the 2031 "highest-priority systems" milestone.
type ncscHighestPriority struct {
	Verdict   ncscVerdict       `json:"verdict"`
	Criteria  string            `json:"criteria"`
	Count     int               `json:"count"`
	Migrated  int               `json:"migratedCount"`
	Remaining int               `json:"remainingCount"`
	Note      string            `json:"note"`
	Findings  []ncscFindingJSON `json:"findings"`
}

// ncscFullMigration is the 2035 "all systems" milestone.
type ncscFullMigration struct {
	Verdict  ncscVerdict       `json:"verdict"`
	Count    int               `json:"count"`
	Findings []ncscFindingJSON `json:"findings"`
}

// ncscReport is the JSON output schema for `--format ncsc`.
type ncscReport struct {
	Standard      string              `json:"standard"`
	GeneratedAt   string              `json:"generatedAt"`
	Root          string              `json:"root"`
	Discovery2028 ncscDiscovery       `json:"discovery2028"`
	Priority2031  ncscHighestPriority `json:"highestPriority2031"`
	Full2035      ncscFullMigration   `json:"fullMigration2035"`
}

// remediationNote explains, in both report formats, why migrated counts are
// always zero: qryx classifies a single point-in-time scan and does not
// persist remediation state across runs. Progress over time is tracked via
// `--baseline` drift or the evidence trail (`--save-evidence` / `qryx
// trend`), not by this report.
const remediationNote = "qryx does not track remediation state across runs within a single scan; remaining = full highest-priority count. Track progress over time with --baseline drift or the evidence trail (--save-evidence / qryx trend)."

// buildNCSC assembles the three milestones from a scan. Shared by the JSON
// (NCSC) and HTML (NCSCHTML) renderers so they can never disagree.
func buildNCSC(res *scan.Result) ncscReport {
	nodes := graph.Build(res.Findings)

	rep := ncscReport{
		Standard:    ncscStandard,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        res.Root,
	}

	// --- 2028 discovery: coverage by source + quantum-vulnerable inventory + plan.
	coverage := map[string]int{}
	total := 0
	for _, n := range nodes {
		for _, o := range n.Occurrences {
			coverage[bucketFor(res.Root, o)]++
			total++
		}
	}
	rep.Discovery2028.CoverageBySource = coverage
	rep.Discovery2028.TotalInventoried = total

	var quantumNodes []graph.AssetNode
	for _, n := range nodes {
		if n.Risk.Class == model.RiskQuantumVulnerable {
			quantumNodes = append(quantumNodes, n)
		}
	}
	sort.SliceStable(quantumNodes, func(i, j int) bool {
		if quantumNodes[i].Risk.Severity != quantumNodes[j].Risk.Severity {
			return quantumNodes[i].Risk.Severity > quantumNodes[j].Risk.Severity
		}
		return assetName(quantumNodes[i]) < assetName(quantumNodes[j])
	})
	rep.Discovery2028.QuantumVulnerable = len(quantumNodes)

	planCovered := 0
	for _, n := range quantumNodes {
		_, planned := planStep(n)
		if planned {
			planCovered++
		}
		rep.Discovery2028.Findings = append(rep.Discovery2028.Findings, findingJSON(n, planned))
	}
	// A plan "exists" when there's nothing that needs one, or when every
	// quantum-vulnerable asset found is covered by the migration plan.
	rep.Discovery2028.PlanExists = len(quantumNodes) == 0 || planCovered == len(quantumNodes)
	rep.Discovery2028.PlanNote = discoveryPlanNote
	if !rep.Discovery2028.PlanExists && planCovered == 0 {
		rep.Discovery2028.PlanNote = "no plan artifact: " + discoveryPlanNote
	}

	switch {
	case total == 0:
		rep.Discovery2028.Verdict = verdictNotStarted
	case len(quantumNodes) > 0 && !rep.Discovery2028.PlanExists:
		rep.Discovery2028.Verdict = verdictAtRisk
	default:
		rep.Discovery2028.Verdict = verdictOnTrack
	}

	// --- 2031 highest-priority: quantum-vulnerable AND (externally-facing or long-lived).
	rep.Priority2031.Criteria = highestPriorityCriteria
	rep.Priority2031.Note = remediationNote
	for _, n := range quantumNodes {
		if !isHighestPriority(n) {
			continue
		}
		_, planned := planStep(n)
		rep.Priority2031.Findings = append(rep.Priority2031.Findings, findingJSON(n, planned))
	}
	rep.Priority2031.Count = len(rep.Priority2031.Findings)
	// Remediation state isn't tracked within a single scan (see remediationNote):
	// nothing is ever counted as migrated here, so remaining == count.
	rep.Priority2031.Migrated = 0
	rep.Priority2031.Remaining = rep.Priority2031.Count

	switch {
	case rep.Discovery2028.Verdict == verdictNotStarted:
		rep.Priority2031.Verdict = verdictNotStarted
	case rep.Priority2031.Count == 0:
		rep.Priority2031.Verdict = verdictOnTrack
	default:
		rep.Priority2031.Verdict = verdictAtRisk
	}

	// --- 2035 full migration: every remaining quantum-vulnerable asset.
	for _, n := range quantumNodes {
		_, planned := planStep(n)
		rep.Full2035.Findings = append(rep.Full2035.Findings, findingJSON(n, planned))
	}
	rep.Full2035.Count = len(rep.Full2035.Findings)

	switch {
	case rep.Discovery2028.Verdict == verdictNotStarted:
		rep.Full2035.Verdict = verdictNotStarted
	case rep.Full2035.Count == 0:
		rep.Full2035.Verdict = verdictOnTrack
	default:
		rep.Full2035.Verdict = verdictAtRisk
	}

	return rep
}

// planStep reports whether agility.Assess recognizes a migration target for
// this asset — the same computation `--format migration` and the dashboard
// use (rankedSteps), reused here as the definition of "planned" per
// discoveryPlanNote.
func planStep(n graph.AssetNode) (target string, planned bool) {
	a, ok := agility.Assess(n)
	if !ok {
		return "", false
	}
	return a.Target, true
}

// NCSC writes the NCSC PQC migration readiness report as JSON.
func NCSC(w io.Writer, res *scan.Result) error {
	rep := buildNCSC(res)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ncscHTMLView is the template data model for the HTML report.
type ncscHTMLView struct {
	Root        string
	GeneratedAt string
	Report      ncscReport
}

// NCSCHTML renders a self-contained NCSC PQC migration readiness HTML report.
func NCSCHTML(w io.Writer, res *scan.Result) error {
	rep := buildNCSC(res)
	v := ncscHTMLView{
		Root:        res.Root,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Report:      rep,
	}
	return ncscTemplate.Execute(w, v)
}

// ncscWhere renders the first location of a finding for the HTML report,
// mirroring dashWhere/firstLoc in the other reports.
func ncscWhere(f ncscFindingJSON) string {
	if len(f.Locations) == 0 {
		return ""
	}
	if extra := len(f.Locations) - 1; extra > 0 {
		return fmt.Sprintf("%s (+%d)", f.Locations[0], extra)
	}
	return f.Locations[0]
}
