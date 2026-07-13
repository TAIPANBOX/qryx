// Package exporter emits qryx findings as agent-event envelopes
// (agent-passport SPEC.md §6), the producer half of the adoption-cost
// table's Qryx row (§9): qryx was already Passport-aware as a consumer
// (internal/agentstack resolves agent_id as an evidence subject), this
// package is the emitter that row calls out as "not started."
//
// Opt-in, fail-open, and never-fabricate-agent_id: the same three rules
// every other emitter in the stack (TokenFuse, Engram, Wardryx, Verdryx,
// Mockryx) already follows. A finding, drifted node, or policy violation
// with no agent_id -- everything outside internal/agentstack's passport
// findings, since code/binary/TLS/cloud-KMS scans have no agent concept
// at all -- is silently skipped rather than invented; see agentIDFromTags.
//
// qryx is one of agent-passport SPEC.md's original four (schema v0.1,
// closed source enum), not a wave-2 service, so events here use
// event.SchemaV01 and source "qryx", matching TokenFuse/Engram/Idryx --
// not Wardryx/Verdryx/Mockryx, which emit v0.2.
package exporter

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
)

const source = "qryx"

// Event type names, per agent-passport SPEC.md §6.2's qryx row
// (`crypto_finding` · `crypto_drift` · `policy_violation` · `evidence_signed`).
const (
	TypeCryptoFinding   = "crypto_finding"
	TypeCryptoDrift     = "crypto_drift"
	TypePolicyViolation = "policy_violation"
	TypeEvidenceSigned  = "evidence_signed"
)

// Exporter wraps an agent-stack-go event.Writer. The zero value is not
// usable; construct with Open.
type Exporter struct {
	w *event.Writer
}

// Open opens path for append (creating it if it does not already exist)
// and returns an Exporter. Callers must Close when done.
func Open(path string) (*Exporter, error) {
	w, err := event.NewWriter(path)
	if err != nil {
		return nil, err
	}
	return &Exporter{w: w}, nil
}

// Close closes the underlying event log file.
func (e *Exporter) Close() error { return e.w.Close() }

// agentIDFromTags returns tags["agent_id"] and whether it was present and
// non-empty -- the one place this package decides whether a real subject
// exists to emit for at all. Only internal/agentstack's passport findings
// ever set this tag (see its findingTags); every other connector's Tags
// has no agent concept, and this deliberately does not fall back to any
// other field as a substitute.
func agentIDFromTags(tags map[string]string) (string, bool) {
	id, ok := tags["agent_id"]
	return id, ok && id != ""
}

// envelopeSeverity maps a qryx model.Severity to the agent-event
// envelope's severity vocabulary (info|low|medium|high|critical, SPEC.md
// §6.1). Every value but SeverityNone already matches Severity.String()
// verbatim; the envelope simply has no "none" level of its own -- an
// event only ever gets emitted for something worth noting at all, so
// SeverityNone folds to "info" rather than being sent as an out-of-enum
// value or invented as a 6th level.
func envelopeSeverity(s model.Severity) string {
	if s == model.SeverityNone {
		return event.SeverityInfo
	}
	return s.String()
}

// EmitFindings emits one crypto_finding event per finding carrying a real
// agent_id.
func (e *Exporter) EmitFindings(findings []model.Finding) error {
	for _, f := range findings {
		agentID, ok := agentIDFromTags(f.Tags)
		if !ok {
			continue
		}
		if err := e.w.Write(event.Event{
			Schema:   event.SchemaV01,
			TS:       nowRFC3339(),
			Source:   source,
			Type:     TypeCryptoFinding,
			AgentID:  agentID,
			Severity: envelopeSeverity(f.Risk.Severity),
			Data: map[string]any{
				"asset_type": string(f.Asset.Type),
				"algorithm":  f.Asset.Algorithm,
				"risk_class": string(f.Risk.Class),
				"evidence":   f.Evidence,
			},
		}); err != nil {
			return fmt.Errorf("exporter: emit %s: %w", TypeCryptoFinding, err)
		}
	}
	return nil
}

// EmitDrift emits one crypto_drift event per newly-appeared asset node
// (store.Delta.Added) carrying a real agent_id -- a node's Tags is the
// union of its occurrences' Tags (see graph.AssetNode), so this reaches
// exactly the same subjects EmitFindings would for the same underlying
// findings, after graph dedup.
func (e *Exporter) EmitDrift(added []graph.AssetNode) error {
	for _, n := range added {
		agentID, ok := agentIDFromTags(n.Tags)
		if !ok {
			continue
		}
		if err := e.w.Write(event.Event{
			Schema:   event.SchemaV01,
			TS:       nowRFC3339(),
			Source:   source,
			Type:     TypeCryptoDrift,
			AgentID:  agentID,
			Severity: envelopeSeverity(n.Risk.Severity),
			Data: map[string]any{
				"asset_type": string(n.Asset.Type),
				"algorithm":  n.Asset.Algorithm,
				"risk_class": string(n.Risk.Class),
				"verdict":    "new",
			},
		}); err != nil {
			return fmt.Errorf("exporter: emit %s: %w", TypeCryptoDrift, err)
		}
	}
	return nil
}

// EmitViolations emits one policy_violation event per violation carrying
// a real agent_id (policy.Violation.Tags, threaded through Evaluate from
// the AssetNode each violation was scored against).
func (e *Exporter) EmitViolations(violations []policy.Violation) error {
	for _, v := range violations {
		agentID, ok := agentIDFromTags(v.Tags)
		if !ok {
			continue
		}
		if err := e.w.Write(event.Event{
			Schema:   event.SchemaV01,
			TS:       nowRFC3339(),
			Source:   source,
			Type:     TypePolicyViolation,
			AgentID:  agentID,
			Severity: envelopeSeverity(v.Severity),
			Data: map[string]any{
				"rule":    v.Rule,
				"asset":   v.Asset,
				"message": v.Message,
			},
		}); err != nil {
			return fmt.Errorf("exporter: emit %s: %w", TypePolicyViolation, err)
		}
	}
	return nil
}

// EmitEvidenceSigned emits one evidence_signed event per distinct
// agent_id present in findings -- signing is a whole-document operation,
// not a per-finding one, so each covered agent gets exactly one event per
// signed evidence document, not one per finding. alg and fingerprint
// mirror attest.Signature.Alg and attest.Fingerprint's own output.
func (e *Exporter) EmitEvidenceSigned(findings []model.Finding, alg, fingerprint string) error {
	seen := map[string]bool{}
	for _, f := range findings {
		agentID, ok := agentIDFromTags(f.Tags)
		if !ok || seen[agentID] {
			continue
		}
		seen[agentID] = true
		if err := e.w.Write(event.Event{
			Schema:   event.SchemaV01,
			TS:       nowRFC3339(),
			Source:   source,
			Type:     TypeEvidenceSigned,
			AgentID:  agentID,
			Severity: event.SeverityInfo,
			Data: map[string]any{
				"alg":         alg,
				"fingerprint": fingerprint,
			},
		}); err != nil {
			return fmt.Errorf("exporter: emit %s: %w", TypeEvidenceSigned, err)
		}
	}
	return nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}
