// Package agentstack is a connector that inventories the cryptography of
// AI-agent infrastructure itself — the trust surface of the agent-governance
// stack, not just the systems it governs. It reads Agent Passport identity
// documents and agent-event NDJSON streams (see
// https://github.com/TAIPANBOX/agent-passport, SPEC.md §4 and §6) and turns
// them into two kinds of finding, strictly on the crypto-hygiene axis:
//
//   - Attestation crypto: what cryptographic binding, if any, backs an
//     agent's identity (its passport's attestation.method).
//   - Event-stream integrity: whether the agent-event NDJSON streams a
//     product emits are hash-chained (tamper-evident) or not. This is a
//     structural check (every event carries a well-formed, non-repeated
//     sha256 prev_hash), not a cryptographic one: see eventStreamFindings.
//
// Identity and privilege (who an agent is, what it can do, whether its
// privilege is excessive) are Idryx's job; this package does not duplicate
// that. It only asks: is there crypto here, and is it sound?
//
// A passport document and an agent-event stream are distinguished by content
// (the "schema" field), not file extension or location, so a directory mixing
// both is handled correctly. Malformed files and malformed lines within an
// otherwise-recognized stream are counted, logged, and skipped — never fatal.
//
// This increment does not probe agent endpoints: nothing in a Passport
// document names a network address today. Once passports (or a future SPEC
// revision) carry an endpoint, a --probe extension that dials the workload
// behind an mtls-cert/spiffe-svid attestation is the natural next step,
// mirroring how internal/probe already inspects live TLS posture.
package agentstack

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

const (
	passportSchema = "taipanbox.dev/agent-passport/v0.1" // #nosec G101 -- schema identifier string ("Passport" substring), not a credential
	eventSchema    = "taipanbox.dev/agent-event/v0.1"
	eventSchemaV02 = "taipanbox.dev/agent-event/v0.2"
)

// passport is the subset of the Agent Passport document (SPEC.md §4) this
// connector needs: the agent identity for evidence text, the owner for the
// shared owner-mapping mechanism, and the attestation method that drives the
// crypto-hygiene judgment.
type passport struct {
	Schema      string `json:"schema"`
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Attestation struct {
		Method string `json:"method"`
		Detail string `json:"detail"`
	} `json:"attestation"`
}

// agentEvent is the subset of the agent-event envelope (SPEC.md §6) this
// connector needs: whether the event carries a tamper-evidence link.
type agentEvent struct {
	Schema   string `json:"schema"`
	AgentID  string `json:"agent_id"`
	PrevHash string `json:"prev_hash"`
}

// Scan reads every file under path — a single file, a directory (walked
// recursively), or a glob pattern — and returns crypto findings for each
// Agent Passport document and agent-event NDJSON stream it recognizes. Files
// that are neither are logged and skipped; malformed passports/event lines
// within a recognized file are counted, logged, and skipped. No input ever
// makes Scan return an error on its own account — only a filesystem failure
// (e.g. path does not exist) does.
func Scan(path string) ([]model.Finding, error) {
	files, err := listFiles(path)
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, f := range files {
		content, err := os.ReadFile(f) // #nosec G304 -- operator-supplied scan path or a file discovered under it
		if err != nil {
			fmt.Fprintf(os.Stderr, "qryx: agentstack: %s: %v\n", f, err)
			continue
		}
		out = append(out, scanFile(f, content)...)
	}
	return out, nil
}

// listFiles resolves path to a flat list of regular files: a glob pattern
// expands (directories among the matches are walked), a directory is walked
// recursively, and a plain file is returned as-is.
func listFiles(path string) ([]string, error) {
	if strings.ContainsAny(path, "*?[") {
		matches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			if info.IsDir() {
				sub, err := walkDir(m)
				if err != nil {
					continue
				}
				out = append(out, sub...)
				continue
			}
			out = append(out, m)
		}
		return out, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return walkDir(path)
	}
	return []string{path}, nil
}

func walkDir(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// scanFile classifies one file by content and maps it to findings. A passport
// is exactly one JSON document for the whole file; anything else is tried as
// an NDJSON agent-event stream (one JSON object per line). A file that is
// neither is logged and skipped.
func scanFile(path string, content []byte) []model.Finding {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil
	}

	var p passport
	if err := json.Unmarshal(trimmed, &p); err == nil && p.Schema == passportSchema {
		return passportFindings(path, p)
	}

	events, malformed := parseEvents(trimmed)
	if len(events) > 0 {
		if malformed > 0 {
			fmt.Fprintf(os.Stderr, "qryx: agentstack: %s: skipped %d malformed event line(s)\n", path, malformed)
		}
		return eventStreamFindings(path, events)
	}

	fmt.Fprintf(os.Stderr, "qryx: agentstack: %s: not a recognized passport or event stream, skipping\n", path)
	return nil
}

// parseEvents reads content as NDJSON, one agent-event object per line. Both
// eventSchema (v0.1) and eventSchemaV02 (v0.2) are accepted per SPEC.md §6.4:
// the two versions differ only in the source field (closed enum vs. open
// string), which this connector doesn't parse, so the same agentEvent fields
// apply to both. Lines that fail to parse, or parse but carry a schema that
// matches neither, are counted as malformed rather than aborting the stream.
func parseEvents(content []byte) (events []agentEvent, malformed int) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e agentEvent
		if err := json.Unmarshal(line, &e); err != nil || (e.Schema != eventSchema && e.Schema != eventSchemaV02) {
			malformed++
			continue
		}
		events = append(events, e)
	}
	return events, malformed
}

// passportFindings maps one passport's attestation method to the crypto asset
// it implies. mtls-cert/spiffe-svid inventory an x509-based identity binding
// with an unknown algorithm (the document alone can't say more); enclave-key
// is a hardware-backed key, the safe end of the spectrum; oidc is token-based
// with no key material visible; none/absent is a misconfig — the identity has
// no cryptographic attestation at all.
func passportFindings(path string, p passport) []model.Finding {
	loc := model.Location{File: path}
	tags := findingTags(p)

	switch p.Attestation.Method {
	case "mtls-cert", "spiffe-svid":
		return []model.Finding{{
			Asset:    model.Asset{Type: model.TypeCertificate, Algorithm: "X509", Primitive: model.PrimitiveUnknown},
			Location: loc,
			Evidence: fmt.Sprintf("agent %s attests via %s (%s)", p.ID, p.Attestation.Method, p.Attestation.Detail),
			Source:   "agentstack",
			Tags:     tags,
		}}
	case "enclave-key":
		return []model.Finding{{
			Asset:    model.Asset{Type: model.TypeKey, Algorithm: "enclave-key", Primitive: model.PrimitiveUnknown},
			Location: loc,
			Evidence: fmt.Sprintf("agent %s attests via hardware enclave key (%s)", p.ID, p.Attestation.Detail),
			Source:   "agentstack",
			Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityNone, Reason: "hardware-backed enclave key attestation"},
			Tags:     tags,
		}}
	case "oidc":
		return []model.Finding{{
			Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "OIDC", Primitive: model.PrimitiveUnknown},
			Location: loc,
			Evidence: fmt.Sprintf("agent %s attests via OIDC token (%s); no key material visible in the passport", p.ID, p.Attestation.Detail),
			Source:   "agentstack",
			Tags:     tags,
		}}
	default: // "none" or absent
		return []model.Finding{{
			Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "no-attestation", Primitive: model.PrimitiveUnknown},
			Location: loc,
			Evidence: fmt.Sprintf("agent %s has no attestation method set", p.ID),
			Source:   "agentstack",
			Risk:     model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityMedium, Reason: "agent identity has no cryptographic attestation"},
			Tags:     tags,
		}}
	}
}

// findingTags builds a passport finding's Tags: always "agent_id" (p.ID --
// a passport document's id is schema-required, so this is never empty for
// a recognized passport), plus "owner" when set, in the shape the shared
// owner-mapping mechanism expects (report.ownerHint checks Owner/owner/
// team/Team/service/Service), mirroring how the cloud connectors map
// owners via tags/labels. "agent_id" is package exporter's only source of
// a real subject to emit a passport finding as an agent-event for (see
// exporter.agentIDFromTags) -- it is not overloaded onto Source or
// Evidence, both of which stay human-readable text, not a stable key.
func findingTags(p passport) map[string]string {
	tags := map[string]string{"agent_id": p.ID}
	if p.Owner != "" {
		tags["owner"] = p.Owner
	}
	return tags
}

// eventStreamFindings judges one NDJSON stream's tamper-evidence. A stream is
// tamper-evident only when EVERY event carries a sha256 prev_hash (all, not
// any: a 1000-event stream with a single chained event is not tamper-evident,
// it just has one chained event) and those hashes are not all the same fixed
// value (a real chain links each event to a different predecessor, so a
// repeated hash is the signature of a dummy/placeholder value rather than a
// genuine one).
//
// This is a structural check, not a cryptographic one. It confirms every
// event carries a sha256:-shaped prev_hash and that the values aren't
// suspiciously repeated, but it does NOT recompute the RFC 8785 (JCS)
// canonical serialization of the preceding event and its sha256 digest to
// confirm prev_hash actually equals hash(prev), per agent-passport SPEC.md
// §6.5. A stream of well-formed, mutually distinct, but fabricated hashes
// would still pass this check; that gap is future work (agent-stack-go's
// event package defines the wire format but no hashing helper to reuse here
// today).
func eventStreamFindings(path string, events []agentEvent) []model.Finding {
	chained := 0
	seen := map[string]bool{}
	duplicate := false
	for _, e := range events {
		if !strings.HasPrefix(e.PrevHash, "sha256:") {
			continue
		}
		chained++
		if seen[e.PrevHash] {
			duplicate = true
		}
		seen[e.PrevHash] = true
	}

	if len(events) > 0 && chained == len(events) && !duplicate {
		return []model.Finding{{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-256", Primitive: model.PrimitiveHash},
			Location: model.Location{File: path},
			Evidence: fmt.Sprintf("event stream is tamper-evident: %d/%d event(s) carry a sha256 prev_hash chain", chained, len(events)),
			Source:   "agentstack",
		}}
	}

	reason := "agent event stream is not tamper-evident (no hash chain)"
	switch {
	case duplicate:
		reason = "agent event stream reuses the same prev_hash value across multiple events (not a genuine per-event chain)"
	case chained > 0:
		reason = "agent event stream is only partially hash-chained: not every event carries a prev_hash"
	}
	return []model.Finding{{
		Asset:    model.Asset{Type: model.TypeProtocol, Algorithm: "no-hash-chain", Primitive: model.PrimitiveHash},
		Location: model.Location{File: path},
		Evidence: fmt.Sprintf("event stream hash-chain covers %d/%d event(s): %s", chained, len(events), reason),
		Source:   "agentstack",
		Risk:     model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityLow, Reason: reason},
	}}
}
