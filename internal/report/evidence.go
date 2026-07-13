package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/TAIPANBOX/qryx/internal/attest"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// evidenceReport is a self-describing, tamper-evident compliance attestation for
// a single scan. It reuses the CNSA 2.0 classification so it never disagrees
// with the `cnsa` report.
type evidenceReport struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	Standard    string            `json:"standard"`
	GeneratedAt string            `json:"generatedAt"`
	Root        string            `json:"root"`
	Summary     evidenceSummary   `json:"summary"`
	Assets      []cnsaAssetJSON   `json:"assets"`
	Digest      string            `json:"digest"`
	Signature   *attest.Signature `json:"signature,omitempty"`
}

type evidenceSummary struct {
	Compliant    int            `json:"compliant"`
	NonCompliant int            `json:"nonCompliant"`
	Issues       int            `json:"issues"`
	Total        int            `json:"total"`
	ScorePct     int            `json:"scorePct"`
	BySeverity   map[string]int `json:"bySeverity"`
}

// Attestation is the summary subset of an evidence document, surfaced for the
// audit trail without exposing the full per-asset records.
type Attestation struct {
	ScorePct     int
	Compliant    int
	NonCompliant int
	Issues       int
	Total        int
	Digest       string
}

// Attest returns the compliance attestation summary for a scan: the same counts
// and integrity digest as the evidence document and dashboard.
func Attest(res *scan.Result, version string) (Attestation, error) {
	rep, err := buildEvidence(res, version)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{
		ScorePct:     rep.Summary.ScorePct,
		Compliant:    rep.Summary.Compliant,
		NonCompliant: rep.Summary.NonCompliant,
		Issues:       rep.Summary.Issues,
		Total:        rep.Summary.Total,
		Digest:       rep.Digest,
	}, nil
}

// Evidence writes a compliance evidence document with an integrity digest. When
// signer is non-nil it adds a detached signature over the digest, making the
// attestation authentic as well as tamper-evident. Returns the resulting
// signature (nil when signer is nil), so a caller emitting an
// evidence_signed agent-event (see internal/exporter) has the alg/
// fingerprint without re-signing the digest a second time.
func Evidence(w io.Writer, res *scan.Result, version string, signer *attest.Signer) (*attest.Signature, error) {
	rep, err := buildEvidence(res, version)
	if err != nil {
		return nil, err
	}
	var sig *attest.Signature
	if signer != nil {
		s, err := signer.Sign([]byte(rep.Digest))
		if err != nil {
			return nil, fmt.Errorf("sign evidence: %w", err)
		}
		rep.Signature = &s
		sig = &s
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return nil, err
	}
	return sig, nil
}

// buildEvidence assembles the evidence report (summary, per-asset records and
// integrity digest) from a scan. Shared by Evidence (JSON) and the dashboard so
// they report identical numbers and the same digest.
func buildEvidence(res *scan.Result, version string) (evidenceReport, error) {
	rep := evidenceReport{
		Tool:        "qryx",
		Version:     version,
		Standard:    "CNSA 2.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        res.Root,
		Summary:     evidenceSummary{BySeverity: map[string]int{}},
	}

	for _, e := range buildEntries(res) {
		switch e.Status {
		case "compliant":
			rep.Summary.Compliant++
		case "non-compliant":
			rep.Summary.NonCompliant++
		case "issue":
			rep.Summary.Issues++
		}
		rep.Summary.Total++
		rep.Assets = append(rep.Assets, assetJSON(e))
	}
	if rep.Summary.Total > 0 {
		rep.Summary.ScorePct = rep.Summary.Compliant * 100 / rep.Summary.Total
	}

	for _, n := range graph.Build(res.Findings) {
		if n.Risk.Class != model.RiskNone {
			rep.Summary.BySeverity[n.Risk.Severity.String()]++
		}
	}

	digest, err := evidenceDigest(rep)
	if err != nil {
		return evidenceReport{}, err
	}
	rep.Digest = "sha256:" + digest
	return rep, nil
}

// VerifyEvidence checks a signed evidence document: it recomputes the content
// digest, confirms it matches the embedded digest, and verifies the signature
// against the embedded public key. It returns the algorithm and key fingerprint
// on success.
func VerifyEvidence(data []byte) (alg, fingerprint string, err error) {
	var rep evidenceReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return "", "", fmt.Errorf("parse evidence: %w", err)
	}
	if rep.Signature == nil {
		return "", "", fmt.Errorf("evidence is not signed")
	}

	want, err := evidenceDigest(rep)
	if err != nil {
		return "", "", err
	}
	if rep.Digest != "sha256:"+want {
		return "", "", fmt.Errorf("digest mismatch: document has been modified")
	}
	if err := attest.Verify([]byte(rep.Digest), *rep.Signature); err != nil {
		return "", "", err
	}
	return rep.Signature.Alg, attest.Fingerprint(*rep.Signature), nil
}

// assetJSON renders one CNSA entry as the shared per-asset record.
func assetJSON(e cnsaEntry) cnsaAssetJSON {
	locs := make([]string, 0, len(e.Node.Occurrences))
	for _, o := range e.Node.Occurrences {
		loc := o.Location.File
		if o.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", o.Location.File, o.Location.Line)
		}
		locs = append(locs, loc)
	}
	return cnsaAssetJSON{
		Algorithm:   assetName(e.Node),
		Type:        string(e.Node.Asset.Type),
		Status:      e.Status,
		Deadline:    e.Deadline,
		Action:      e.Action,
		Occurrences: len(e.Node.Occurrences),
		Locations:   locs,
		Tags:        e.Node.Tags,
	}
}

// evidenceDigest is the sha256 of the report serialized with an empty Digest,
// so a verifier can recompute it by blanking the field. Deterministic:
// encoding/json sorts string-keyed maps and entries are pre-sorted.
func evidenceDigest(rep evidenceReport) (string, error) {
	rep.Digest = ""
	rep.Signature = nil
	raw, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
