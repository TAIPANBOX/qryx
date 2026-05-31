package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// evidenceReport is a self-describing, tamper-evident compliance attestation for
// a single scan. It reuses the CNSA 2.0 classification so it never disagrees
// with the `cnsa` report.
type evidenceReport struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	Standard    string          `json:"standard"`
	GeneratedAt string          `json:"generatedAt"`
	Root        string          `json:"root"`
	Summary     evidenceSummary `json:"summary"`
	Assets      []cnsaAssetJSON `json:"assets"`
	Digest      string          `json:"digest"`
}

type evidenceSummary struct {
	Compliant    int            `json:"compliant"`
	NonCompliant int            `json:"nonCompliant"`
	Issues       int            `json:"issues"`
	Total        int            `json:"total"`
	ScorePct     int            `json:"scorePct"`
	BySeverity   map[string]int `json:"bySeverity"`
}

// Evidence writes a compliance evidence document with an integrity digest.
func Evidence(w io.Writer, res *scan.Result, version string) error {
	rep, err := buildEvidence(res, version)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
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
	raw, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
