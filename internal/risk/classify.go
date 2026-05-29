package risk

import (
	"fmt"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// Classify assigns a Risk to an asset based on its algorithm and key size.
// Unknown algorithms get RiskNone so detectors stay responsible for what they
// assert; the classifier never invents risk it cannot justify.
func Classify(a model.Asset) model.Risk {
	key := NormalizeAlgorithm(a.Algorithm)
	bc, known := baseline[key]
	if !known {
		return model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}
	}

	risk := model.Risk{Class: bc.class, Severity: bc.sev, Reason: bc.reason}

	// Key-size refinement for RSA: short keys are weak today, not just
	// quantum-vulnerable tomorrow.
	if key == "RSA" && a.KeySize > 0 && a.KeySize < 2048 {
		risk.Class = model.RiskWeak
		risk.Severity = model.SeverityCritical
		risk.Reason = fmt.Sprintf("RSA-%d is below the 2048-bit minimum and weak today", a.KeySize)
	}

	return risk
}
