package exporter

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
)

// A write that fails is returned, named by the event type that was being
// emitted, by every emitter: an event log that silently stops recording is the
// failure an audit trail cannot have.
func TestEveryEmitterReturnsAFailedWrite(t *testing.T) {
	e, _ := mustOpen(t)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	tags := withAgentID(nil, "agent://acme.example/bot")
	f := []model.Finding{{Asset: model.Asset{Algorithm: "RSA"}, Tags: tags}}

	for typ, emit := range map[string]func() error{
		TypeCryptoFinding:   func() error { return e.EmitFindings(f) },
		TypeCryptoDrift:     func() error { return e.EmitDrift([]graph.AssetNode{{Asset: f[0].Asset, Tags: tags}}) },
		TypePolicyViolation: func() error { return e.EmitViolations([]policy.Violation{{Rule: "r", Tags: tags}}) },
		TypeEvidenceSigned:  func() error { return e.EmitEvidenceSigned(f, "ed25519", "sha256:00") },
	} {
		err := emit()
		if err == nil || !strings.Contains(err.Error(), "emit "+typ) {
			t.Errorf("%s on a closed log: got %v, want an error naming the event type", typ, err)
		}
	}
}

// The preview is the chain prefix plus twelve hex characters; anything already
// that short is shown whole rather than cut.
func TestChainPreview(t *testing.T) {
	full := event.ChainHashPrefix + strings.Repeat("ab", 32)
	if got := ChainPreview(full); got != event.ChainHashPrefix+"abababababab" {
		t.Errorf("ChainPreview(full) = %q", got)
	}
	short := event.ChainHashPrefix + "abc"
	if got := ChainPreview(short); got != short {
		t.Errorf("ChainPreview(short) = %q", got)
	}
}
