package detectors

import (
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// cryptoLib maps a dependency-name substring to the algorithm family it implies.
// Phase 0 reports the presence of crypto libraries as inventory; version-level
// CVE matching is a later phase.
var cryptoLibs = []struct {
	needle string
	algo   string
}{
	{"pycryptodome", "AES"},
	{"pycrypto", "AES"},
	{"cryptography", "RSA"},
	{"bcrypt", "bcrypt"},
	{"pyopenssl", "RSA"},
	{"node-forge", "RSA"},
	{"crypto-js", "AES"},
	{"bouncycastle", "RSA"},
	{"openssl", "RSA"},
}

// Deps detects cryptographic libraries declared in dependency manifests.
type Deps struct{}

func NewDeps() *Deps { return &Deps{} }

func (d *Deps) Name() string { return "deps" }

func (d *Deps) Wants(path string) bool {
	switch filepath.Base(path) {
	case "go.mod", "requirements.txt", "package.json", "Cargo.toml", "pom.xml":
		return true
	}
	return false
}

func (d *Deps) Detect(f scan.File) []model.Finding {
	var out []model.Finding
	lower := strings.ToLower(string(f.Content))
	for _, lib := range cryptoLibs {
		idx := strings.Index(lower, lib.needle)
		if idx < 0 {
			continue
		}
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeLibrary,
				Algorithm: lib.algo,
				Primitive: model.PrimitiveUnknown,
			},
			Location: model.Location{File: f.Path, Line: lineNumber(f.Content, idx)},
			Evidence: "depends on " + lib.needle,
			Source:   d.Name(),
		})
	}
	return out
}
