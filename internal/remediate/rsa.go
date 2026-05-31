package remediate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// rsaKeySize raises rsa.GenerateKey(rand, <literal>) calls whose key size is
// below the configured floor. Only integer-literal sizes are touched — a
// variable size has no single safe value to substitute. The change is one int
// literal, so the result always parses and compiles.
type rsaKeySize struct{}

func (rsaKeySize) name() string { return "rsa-key-size" }

func (rsaKeySize) apply(content string, findings []model.Finding, cfg Config) (string, string, bool) {
	if !hasSubFloorRSA(findings, cfg.MinRSABits) {
		return "", "", false
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", content, 0)
	if err != nil {
		return "", "", false
	}
	aliases := rsaAliases(file)
	if len(aliases) == 0 {
		return "", "", false
	}

	type edit struct {
		off, length int
	}
	var edits []edit
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "GenerateKey" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !aliases[pkg.Name] || len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return true
		}
		bits, err := strconv.Atoi(lit.Value)
		if err != nil || bits >= cfg.MinRSABits {
			return true
		}
		edits = append(edits, edit{off: fset.Position(lit.Pos()).Offset, length: len(lit.Value)})
		return true
	})
	if len(edits) == 0 {
		return "", "", false
	}

	// Apply largest offset first so earlier offsets stay valid.
	sort.Slice(edits, func(i, j int) bool { return edits[i].off > edits[j].off })
	out := content
	repl := strconv.Itoa(cfg.MinRSABits)
	for _, e := range edits {
		out = out[:e.off] + repl + out[e.off+e.length:]
	}

	// Defensive: a token swap must never produce unparseable code.
	if _, err := parser.ParseFile(token.NewFileSet(), "", out, 0); err != nil {
		return "", "", false
	}

	rationale := fmt.Sprintf("raise sub-%d-bit RSA keys to %d (CNSA 2.0 interim; migrate to ML-DSA/ML-KEM for PQC)", cfg.MinRSABits, cfg.MinRSABits)
	return out, rationale, true
}

func hasSubFloorRSA(findings []model.Finding, floor int) bool {
	for _, f := range findings {
		if f.Source == "goast" && f.Asset.Algorithm == "RSA" && f.Asset.KeySize > 0 && f.Asset.KeySize < floor {
			return true
		}
	}
	return false
}

// rsaAliases returns the identifiers bound to the crypto/rsa import in file.
func rsaAliases(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != "crypto/rsa" {
			continue
		}
		name := "rsa"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = true
	}
	return out
}
