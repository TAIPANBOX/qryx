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
//
// "not-assessed" is a verdict, not a gap in this type: it says qryx has no
// CNSA 2.0 rule covering that algorithm and did not grade it. It exists
// because the alternative, which this report used to do, is to call
// everything it does not recognize compliant, and a compliance score is only
// worth reading if not knowing looks different from passing.
type cnsaEntry struct {
	Node     graph.AssetNode
	Status   string // "compliant" | "non-compliant" | "issue" | "not-assessed"
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
			Action: misconfigAction(n)}
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
		// A missing size is not a passing size. CNSA 2.0 approves AES at 256
		// bits and nothing below it, so grading a sizeless AES asset compliant
		// asserts the one fact the scan never established, and asserts it in
		// the operator's favour. This branch used to fold `KeySize == 0` in
		// with `>= 256` and tell the reader "AES-256 is the CNSA 2.0 approved
		// symmetric cipher" about a key whose length it had never seen.
		//
		// The unknown is the common case, not an edge one. Eight of the twelve
		// places that build an AES asset leave the size at zero: Azure Key
		// Vault oct and oct-HSM keys, where it is genuinely unknowable from
		// public metadata while Key Vault and Managed HSM both accept 128 and
		// 192-bit keys; the same key declared in Terraform; a `crypto/aes`
		// import; the `AES_` and `EVP_aes_` symbol rules in binscan; and the
		// three identifier patterns in the rust and cryptocall detectors. The
		// four that do supply 256 all read a provider's symmetric default:
		// AWS KMS, GCP KMS, and Terraform's aws and google equivalents.
		//
		// Two of those six match text that names the size on the matched line
		// (`Aes128Gcm`, `createCipheriv('aes-128-cbc', ...)`) and still do not
		// read it, because the patterns anchor on the cipher name. So this was
		// not only an unknown counted as a pass: it printed a specific wrong
		// number over a source line that said otherwise. Teaching those
		// detectors to extract a size would shrink this branch's population
		// but cannot empty it, because the Key Vault case has no size to read.
		switch {
		case n.Asset.KeySize == 0:
			return cnsaEntry{Node: n, Status: "not-assessed", Deadline: "n/a",
				Action: "Not assessed: qryx could not determine the AES key size, and CNSA 2.0 approves AES only at 256 bits. Check the configured key length where the key is created, at the location listed; AES-128 and AES-192 are not compliant."}
		case n.Asset.KeySize >= 256:
			return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
				Action: "AES-256 is the CNSA 2.0 approved symmetric cipher."}
		default:
			return cnsaEntry{Node: n, Status: "non-compliant", Deadline: "immediate",
				Action: fmt.Sprintf("AES-%d is below the CNSA 2.0 minimum of 256 bits. Upgrade to AES-256.", n.Asset.KeySize)}
		}
	case "SHA384", "SHA512":
		return cnsaEntry{Node: n, Status: "compliant", Deadline: "n/a",
			Action: "SHA-384/512 is the CNSA 2.0 approved hash function."}
	}

	// Everything else: no rule above matched, so this tool has not graded the
	// asset against CNSA 2.0 and must not imply that it did.
	//
	// This branch used to return "compliant" with "No CNSA 2.0 restriction
	// identified", which was false for every asset that reached it. SHA-256 is
	// not on the CNSA 2.0 list; bcrypt, HMAC and ChaCha20 are simply outside
	// the suite; X509, OIDC and enclave-key are the pseudo-assets `qryx
	// agents` emits for a passport's attestation method; and any algorithm
	// risk.Classify has never heard of lands here too. Counting them as passes
	// inflated ScorePct, which is what `--format evidence` signs and what
	// `qryx trend --fail-on-regression` gates on: a scan of entirely
	// unrecognized cryptography scored 100%.
	return cnsaEntry{Node: n, Status: "not-assessed", Deadline: "n/a",
		Action: fmt.Sprintf("Not assessed: qryx has no CNSA 2.0 rule for %s. It is neither approved nor rejected here; grade it by hand before relying on the score.", n.Asset.Algorithm)}
}

// misconfigAction picks the remediation for a misconfiguration from what the
// finding actually is, not from its risk class alone.
//
// Risk class says how bad a thing is, never what it is: "misconfig" covers a
// server offering TLS 1.0, an Agent Passport with no attestation method, and
// an agent-event stream with no prev_hash chain. This used to return the TLS
// line for all three, so the compliance pack told an operator to enforce TLS
// 1.3 to fix an unsigned agent identity.
//
// The smallest discriminator that separates them is the asset's algorithm,
// which is the field each connector already sets to say what it found: the
// pseudo-algorithms "no-attestation", "no-hash-chain", "hash-chain-broken"
// and "hash-chain-unverifiable" come from internal/agentstack
// (passportFindings / eventStreamFindings), and every TLS misconfiguration
// arrives as a protocol named TLS or SSL from internal/probe or the
// tlsconfig detector. The two chain verdicts get their own sentences because
// their fix is the opposite of no-hash-chain's: nothing to add, something to
// find (a rewrite after hashing) or to repair (a line that is not an event).
//
// The default is deliberately not the TLS line. A misconfiguration this
// report has no rule for gets the detector's own reason and an admission that
// there is no CNSA 2.0 remediation specific to it, so the next connector to
// add a misconfig class inherits an honest answer rather than a wrong one.
func misconfigAction(n graph.AssetNode) string {
	algo := strings.ToUpper(strings.TrimSpace(n.Asset.Algorithm))
	switch algo {
	case "NO-ATTESTATION":
		return "Agent Passport declares no attestation method; bind the identity to real key material (mTLS certificate, SPIFFE SVID or enclave key) per agent-passport SPEC.md §4."
	case "NO-HASH-CHAIN":
		return "Agent event stream is not tamper-evident; emit a distinct sha256 prev_hash on every event so the log is chained, per agent-passport SPEC.md §6.5."
	case "HASH-CHAIN-BROKEN":
		return "Agent event stream fails cryptographic chain verification: a prev_hash is not the sha256 of the RFC 8785 canonical form of the event before it, so the log is not tamper-evident from the first break onward; treat the events after it as unverified, find what rewrote them after they were hashed, and re-emit through a writer that computes prev_hash per agent-passport SPEC.md §6.5."
	case "HASH-CHAIN-UNVERIFIABLE":
		return "Agent event stream could not be verified in full: malformed lines left the events after them unchecked, so tamper-evidence is unproven rather than disproven; repair or remove the lines that are not one JSON event each, fix the producer that wrote them, and re-run, so every prev_hash can be recomputed per agent-passport SPEC.md §6.5."
	}
	if strings.HasPrefix(algo, "TLS") || strings.HasPrefix(algo, "SSL") {
		return "TLS misconfiguration; enforce TLS 1.3 per CNSA 2.0."
	}
	if n.Risk.Reason != "" {
		return fmt.Sprintf("%s. Fix what that names: qryx has no CNSA 2.0 remediation specific to %s.", n.Risk.Reason, n.Asset.Algorithm)
	}
	return fmt.Sprintf("%s is misconfigured. qryx has no CNSA 2.0 remediation specific to it; review the configuration that produced it.", n.Asset.Algorithm)
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

// cnsaSummary carries all four counts, always, including the zero ones.
//
// The split is the point: 60% compliant out of an inventory this tool graded
// completely and 60% out of one where a third was never assessed are different
// facts, and a reader who is shown only the score cannot tell them apart.
// NotAssessed is counted in Total, so it is in the denominator of the score:
// leaving it out would let a scan of nothing but unrecognized cryptography
// report 100%, which is the exact defect the third status exists to close.
type cnsaSummary struct {
	Compliant    int `json:"compliant"`
	NonCompliant int `json:"nonCompliant"`
	Issues       int `json:"issues"`
	NotAssessed  int `json:"notAssessed"`
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
		case "not-assessed":
			rep.Summary.NotAssessed++
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
//
// Nodes are filtered to cryptographic asset types first: CNSA 2.0 is a
// cryptography standard, so grading a non-cryptographic inventory fact (e.g.
// an ai-usage finding) against it and calling the result "compliant" would
// misrepresent both the finding and the report, and, via buildEvidence and
// the dashboard which both reuse this, would quietly dilute the CNSA
// compliance score with something that was never a cryptography question in
// the first place. See model.AssetType.IsCryptographic.
func buildEntries(res *scan.Result) []cnsaEntry {
	all := graph.Build(res.Findings)
	nodes := make([]graph.AssetNode, 0, len(all))
	for _, n := range all {
		if n.Asset.Type.IsCryptographic() {
			nodes = append(nodes, n)
		}
	}
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
	NotAssessed       []cnsaEntry
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
		case "not-assessed":
			v.Summary.NotAssessed++
			v.NotAssessed = append(v.NotAssessed, e)
		}
	}
	v.Summary.Total = v.Summary.Compliant + v.Summary.NonCompliant + v.Summary.Issues + v.Summary.NotAssessed
	if v.Summary.Total > 0 {
		v.ScorePct = v.Summary.Compliant * 100 / v.Summary.Total
	}
	return cnsaTemplate.Execute(w, v)
}
