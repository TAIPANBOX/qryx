package detectors

import (
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// cryptoLibs are dependency names that say a project ships a cryptography
// library, and say nothing else.
//
// They used to carry an algorithm each: `cryptography`, `pyopenssl`,
// `node-forge`, `bouncycastle` and `openssl` all mapped to "RSA". Since
// risk.Classify keys purely on the algorithm name, with no regard for asset
// type, a plain `cryptography>=42` line in a requirements.txt became an RSA
// quantum-vulnerable HIGH asset: counted against the CNSA 2.0 score, listed in
// the NCSC 2035 migration set, given a migration-plan entry, and able to trip
// `--fail-on high`. None of that was in the manifest. pyca/cryptography
// exposes RSA, ECDSA, Ed25519, AES, ChaCha20, HKDF and Fernet; a dependency on
// it means an operator might use any of them, or none, and which one is a
// question only the code can answer. The `goast`, `cryptocall` and `rust`
// detectors are the ones that read the code.
//
// So the library is inventoried under its own name, which is the only thing
// the manifest actually states. CLAUDE.md's detector rule is signal quality
// over recall: a finding that asserts more than its evidence supports is a
// false positive wearing a severity.
var cryptoLibs = []string{
	"pycryptodome",
	"pycrypto",
	"cryptography",
	"bcrypt",
	"pyopenssl",
	"node-forge",
	"crypto-js",
	"bouncycastle",
	"openssl",
}

// depRisk is asserted on every finding this detector produces rather than left
// for risk.Apply to fill in, exactly as aiusage.go does and for the same
// reason: a declared dependency is an inventory fact, not a graded weakness,
// and it must not be able to become one by accident if a future entry in the
// risk baseline happens to share a library's name.
//
// RiskNone with SeverityInfo means it is structurally exempt from --fail-on,
// --fail-on-new and every --policy rule (all of which gate on
// `Risk.Class != model.RiskNone`), it carries no CNSA 2.0 verdict, and it is
// never in the NCSC migration set. It stays fully visible in the human, HTML,
// CBOM and drift views, which is where a crypto library belongs.
var depRisk = model.Risk{
	Class:    model.RiskNone,
	Severity: model.SeverityInfo,
	Reason:   "cryptography library declared in a dependency manifest; the manifest does not say which primitives the code uses",
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

// Detect reports one finding per library per line that declares it.
//
// Per line, rather than per file: strings.Index only ever found the first
// mention, so a package.json naming node-forge in both dependencies and
// devDependencies reported one of them and the operator had no way to see the
// other. Per line rather than per match, because a line is one declaration:
// counting a name twice within it would inflate the occurrence count without
// pointing anywhere new.
func (d *Deps) Detect(f scan.File) []model.Finding {
	var out []model.Finding
	for i, raw := range strings.Split(string(f.Content), "\n") {
		lower := strings.ToLower(raw)
		var named []string
		for _, lib := range cryptoLibs {
			if strings.Contains(lower, lib) {
				named = append(named, lib)
			}
		}
		for _, lib := range named {
			// The most specific name on the line wins: "openssl" is a
			// substring of "pyopenssl" and "pycrypto" of "pycryptodome", so a
			// single `pyopenssl==24.0` line used to report a second, imaginary
			// dependency on openssl beside it.
			if shadowed(lib, named) {
				continue
			}
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeLibrary,
					Algorithm: lib,
					Primitive: model.PrimitiveUnknown,
				},
				Location: model.Location{File: f.Path, Line: i + 1},
				Evidence: "declares a dependency on " + lib,
				Source:   d.Name(),
				Risk:     depRisk,
			})
		}
	}
	return out
}

// shadowed reports whether another library named on the same line contains
// this one's name, which makes this one a substring match rather than a
// separate dependency.
func shadowed(lib string, named []string) bool {
	for _, other := range named {
		if other != lib && strings.Contains(other, lib) {
			return true
		}
	}
	return false
}
