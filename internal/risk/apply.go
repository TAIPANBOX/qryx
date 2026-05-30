package risk

import "github.com/TAIPANBOX/qryx/internal/model"

// Apply classifies, in place, every finding whose risk class is unset.
// Algorithm-based findings leave Risk empty for uniform classification here;
// context-based detectors (TLS misconfig, hardcoded keys, expired certs) assert
// their own Risk and are left untouched.
func Apply(findings []model.Finding) []model.Finding {
	for i := range findings {
		if findings[i].Risk.Class == "" {
			findings[i].Risk = Classify(findings[i].Asset)
		}
	}
	return findings
}
