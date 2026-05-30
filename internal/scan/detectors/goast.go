package detectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// goPkg is the asset implied by importing a standard-library crypto package.
type goPkg struct {
	algo string
	prim model.Primitive
}

// goCryptoPkgs maps a crypto import path to the asset it implies. Unlike regex
// matching, resolving real imports and call sites ignores comments, docs and
// string literals that merely mention "crypto/rsa".
var goCryptoPkgs = map[string]goPkg{
	"crypto/md5":     {"MD5", model.PrimitiveHash},
	"crypto/sha1":    {"SHA-1", model.PrimitiveHash},
	"crypto/sha256":  {"SHA-256", model.PrimitiveHash},
	"crypto/sha512":  {"SHA-512", model.PrimitiveHash},
	"crypto/des":     {"DES", model.PrimitiveEncryption},
	"crypto/rc4":     {"RC4", model.PrimitiveEncryption},
	"crypto/aes":     {"AES", model.PrimitiveEncryption},
	"crypto/rsa":     {"RSA", model.PrimitiveSignature},
	"crypto/ecdsa":   {"ECDSA", model.PrimitiveSignature},
	"crypto/ed25519": {"Ed25519", model.PrimitiveSignature},
	"crypto/dsa":     {"DSA", model.PrimitiveSignature},
	"crypto/ecdh":    {"ECDH", model.PrimitiveKeyExch},
}

// GoAST detects cryptographic usage in Go source via the standard go/ast
// parser: it resolves imported crypto packages and reports each call site,
// extracting the RSA key size from rsa.GenerateKey when it is a literal.
type GoAST struct{}

func NewGoAST() *GoAST { return &GoAST{} }

func (g *GoAST) Name() string { return "goast" }

func (g *GoAST) Wants(path string) bool { return filepath.Ext(path) == ".go" }

func (g *GoAST) Detect(f scan.File) []model.Finding {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, f.Path, f.Content, 0)
	if err != nil {
		return nil // a parse error in one file must not break the scan
	}

	// Resolve local import alias -> crypto package metadata.
	aliases := map[string]goPkg{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		meta, ok := goCryptoPkgs[p]
		if !ok {
			continue
		}
		name := pkgName(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		aliases[name] = meta
	}
	if len(aliases) == 0 {
		return nil
	}

	// Single walk. A selector on a crypto package (md5.New, rsa.PublicKey) is
	// real usage whether called, passed as a value (hmac.New(md5.New, ...)), or
	// referenced as a type. When the selector IS a call's function, we record
	// its position so the selector visit does not double-emit, and we extract
	// the RSA key size from rsa.GenerateKey(rand, bits) onto that one finding.
	var out []model.Finding
	handled := map[token.Pos]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, meta, ok := cryptoSelector(node.Fun, aliases)
			if !ok {
				return true
			}
			handled[sel.Pos()] = true
			asset := model.Asset{Type: model.TypeAlgorithm, Algorithm: meta.algo, Primitive: meta.prim}
			if meta.algo == "RSA" {
				asset.KeySize = rsaKeyBits(sel.Sel.Name, node)
			}
			out = append(out, finding(f.Path, fset, sel, asset, g.Name(), "(...)"))
		case *ast.SelectorExpr:
			if handled[node.Pos()] {
				return true
			}
			_, meta, ok := cryptoSelector(node, aliases)
			if !ok {
				return true
			}
			asset := model.Asset{Type: model.TypeAlgorithm, Algorithm: meta.algo, Primitive: meta.prim}
			out = append(out, finding(f.Path, fset, node, asset, g.Name(), ""))
		}
		return true
	})
	return out
}

// cryptoSelector reports whether expr is a selector on an imported crypto
// package, returning the selector and its package metadata.
func cryptoSelector(expr ast.Expr, aliases map[string]goPkg) (*ast.SelectorExpr, goPkg, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return nil, goPkg{}, false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, goPkg{}, false
	}
	meta, ok := aliases[pkgIdent.Name]
	return sel, meta, ok
}

func finding(path string, fset *token.FileSet, sel *ast.SelectorExpr, asset model.Asset, source, suffix string) model.Finding {
	pkgIdent := sel.X.(*ast.Ident)
	return model.Finding{
		Asset:    asset,
		Location: model.Location{File: path, Line: fset.Position(sel.Pos()).Line},
		Evidence: pkgIdent.Name + "." + sel.Sel.Name + suffix,
		Source:   source,
	}
}

// rsaKeyBits extracts the bit size from rsa.GenerateKey(rand, bits); 0 when the
// size is not an integer literal.
func rsaKeyBits(fn string, call *ast.CallExpr) int {
	if fn != "GenerateKey" || len(call.Args) < 2 {
		return 0
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0
	}
	return n
}

// pkgName returns the default package identifier for an import path.
func pkgName(importPath string) string {
	return filepath.Base(importPath)
}
