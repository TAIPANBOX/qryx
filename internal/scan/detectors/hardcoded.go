package detectors

import (
	"path/filepath"
	"regexp"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// rePrivateKey matches PEM private-key headers of any flavor.
var rePrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)

// sourceExts are file types where an embedded private key is almost certainly a
// mistake. Dedicated .key/.pem files are handled as expected key material, not
// as hardcoded secrets.
var sourceExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".mjs": true,
	".jsx": true, ".tsx": true, ".rs": true, ".java": true, ".rb": true,
	".env": true, ".yaml": true, ".yml": true, ".json": true, ".tf": true,
}

// Hardcoded flags private-key material embedded in source or config files.
type Hardcoded struct{}

func NewHardcoded() *Hardcoded { return &Hardcoded{} }

func (h *Hardcoded) Name() string { return "hardcoded" }

func (h *Hardcoded) Wants(path string) bool {
	return sourceExts[filepath.Ext(path)]
}

func (h *Hardcoded) Detect(f scan.File) []model.Finding {
	var out []model.Finding
	for _, loc := range rePrivateKey.FindAllIndex(f.Content, -1) {
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeKey,
				Algorithm: "private-key",
				Primitive: model.PrimitiveUnknown,
			},
			Location: model.Location{File: f.Path, Line: lineNumber(f.Content, loc[0])},
			Evidence: string(f.Content[loc[0]:loc[1]]),
			Source:   h.Name(),
			Risk: model.Risk{
				Class:    model.RiskHardcoded,
				Severity: model.SeverityCritical,
				Reason:   "private key material embedded in source/config",
			},
		})
	}
	return out
}
