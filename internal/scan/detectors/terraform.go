package detectors

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Terraform detects cryptographic key material declared in HCL using the
// official hashicorp/hcl parser: it reads only well-known crypto resource
// attributes, evaluates statically (literal) expressions, and treats
// interpolated/variable values as unknown rather than guessing. One asset per
// resource; risk is left to the central classifier.
type Terraform struct{}

func NewTerraform() *Terraform { return &Terraform{} }

func (t *Terraform) Name() string { return "terraform" }

func (t *Terraform) Wants(path string) bool { return filepath.Ext(path) == ".tf" }

func (t *Terraform) Detect(f scan.File) []model.Finding {
	file, _ := hclsyntax.ParseConfig(f.Content, f.Path, hcl.InitialPos)
	if file == nil {
		return nil
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}

	var out []model.Finding
	for _, b := range body.Blocks {
		if b.Type != "resource" || len(b.Labels) == 0 {
			continue
		}
		switch b.Labels[0] {
		case "tls_private_key":
			out = appendIf(out, t.tlsPrivateKey(f, b))
		case "aws_kms_key":
			out = appendIf(out, t.awsKMSKey(f, b))
		case "azurerm_key_vault_key":
			out = appendIf(out, t.azureKey(f, b))
		case "google_kms_crypto_key":
			out = appendIf(out, t.googleKMSKey(f, b))
		}
	}
	return out
}

func (t *Terraform) tlsPrivateKey(f scan.File, b *hclsyntax.Block) *model.Finding {
	algo := "RSA"
	if v, _, ok := attrStatic(b.Body, "algorithm"); ok {
		algo = ctyString(v)
	}
	switch algo {
	case "RSA":
		size := 2048 // Terraform default when rsa_bits is omitted.
		line := blockLine(b)
		if v, present, static := attrStatic(b.Body, "rsa_bits"); present {
			line = attrLine(b.Body, "rsa_bits")
			if static {
				size = ctyInt(v)
			} else {
				size = 0 // variable/interpolated: unknown, do not guess.
			}
		}
		return t.key(f, line, "RSA", size, model.PrimitiveSignature, `algorithm = "RSA"`)
	case "ECDSA":
		return t.key(f, blockLine(b), "ECDSA", 0, model.PrimitiveSignature, `algorithm = "ECDSA"`)
	}
	return nil
}

func (t *Terraform) awsKMSKey(f scan.File, b *hclsyntax.Block) *model.Finding {
	spec := "SYMMETRIC_DEFAULT"
	line := blockLine(b)
	if v, present, static := attrStatic(b.Body, "customer_master_key_spec"); present && static {
		spec = ctyString(v)
		line = attrLine(b.Body, "customer_master_key_spec")
	}
	algo, size, prim := kmsSpecAsset(spec)
	return t.key(f, line, algo, size, prim, "customer_master_key_spec = "+strconv.Quote(spec))
}

func (t *Terraform) azureKey(f scan.File, b *hclsyntax.Block) *model.Finding {
	v, _, static := attrStatic(b.Body, "key_type")
	if !static {
		return nil
	}
	kt := ctyString(v)
	line := attrLine(b.Body, "key_type")
	ev := "key_type = " + strconv.Quote(kt)
	switch kt {
	case "RSA", "RSA-HSM":
		size := 2048
		if sv, _, ok := attrStatic(b.Body, "key_size"); ok {
			size = ctyInt(sv)
		}
		return t.key(f, line, "RSA", size, model.PrimitiveSignature, ev)
	case "EC", "EC-HSM":
		return t.key(f, line, "ECDSA", 0, model.PrimitiveSignature, ev)
	case "oct", "oct-HSM":
		return t.key(f, line, "AES", 0, model.PrimitiveEncryption, ev)
	}
	return nil
}

func (t *Terraform) googleKMSKey(f scan.File, b *hclsyntax.Block) *model.Finding {
	// The algorithm lives in a nested version_template block.
	for _, nb := range b.Body.Blocks {
		if nb.Type != "version_template" {
			continue
		}
		v, _, static := attrStatic(nb.Body, "algorithm")
		if !static {
			return nil
		}
		alg := ctyString(v)
		algo, size, prim := googleAlgAsset(alg)
		if algo == "" {
			return nil
		}
		return t.key(f, attrLine(nb.Body, "algorithm"), algo, size, prim, "algorithm = "+strconv.Quote(alg))
	}
	return nil
}

// key builds a finding for an asset at the given 1-based line.
func (t *Terraform) key(f scan.File, line int, algo string, size int, prim model.Primitive, ev string) *model.Finding {
	return &model.Finding{
		Asset:    model.Asset{Type: model.TypeKey, Algorithm: algo, KeySize: size, Primitive: prim},
		Location: model.Location{File: f.Path, Line: line},
		Evidence: ev,
		Source:   t.Name(),
	}
}

func appendIf(out []model.Finding, f *model.Finding) []model.Finding {
	if f != nil {
		out = append(out, *f)
	}
	return out
}

var reDigits = regexp.MustCompile(`(\d{3,4})`)

// kmsSpecAsset maps an aws_kms_key customer_master_key_spec to an asset.
func kmsSpecAsset(spec string) (algo string, size int, prim model.Primitive) {
	switch {
	case strings.HasPrefix(spec, "RSA_"):
		size := 0
		if m := reDigits.FindString(spec); m != "" {
			size, _ = strconv.Atoi(m)
		}
		return "RSA", size, model.PrimitiveSignature
	case strings.HasPrefix(spec, "ECC_"):
		return "ECDSA", 0, model.PrimitiveSignature
	case strings.HasPrefix(spec, "HMAC_"):
		return "HMAC", 0, model.PrimitiveUnknown
	default: // SYMMETRIC_DEFAULT
		return "AES", 256, model.PrimitiveEncryption
	}
}

// googleAlgAsset maps a google_kms_crypto_key version_template algorithm.
func googleAlgAsset(alg string) (algo string, size int, prim model.Primitive) {
	switch {
	case strings.HasPrefix(alg, "RSA_"):
		size := 0
		if m := reDigits.FindString(alg); m != "" {
			size, _ = strconv.Atoi(m)
		}
		return "RSA", size, model.PrimitiveSignature
	case strings.HasPrefix(alg, "EC_"):
		return "ECDSA", 0, model.PrimitiveSignature
	case strings.HasPrefix(alg, "HMAC"):
		return "HMAC", 0, model.PrimitiveUnknown
	case strings.Contains(alg, "SYMMETRIC"):
		return "AES", 256, model.PrimitiveEncryption
	default:
		return "", 0, model.PrimitiveUnknown
	}
}

// attrStatic returns an attribute's statically-evaluated value. present reports
// whether the attribute exists; static reports whether it evaluated without
// diagnostics (a literal, not a variable/function reference).
func attrStatic(body *hclsyntax.Body, name string) (val cty.Value, present, static bool) {
	a, ok := body.Attributes[name]
	if !ok {
		return cty.NilVal, false, false
	}
	v, diags := a.Expr.Value(nil)
	if diags.HasErrors() {
		return cty.NilVal, true, false
	}
	return v, true, true
}

func attrLine(body *hclsyntax.Body, name string) int {
	if a, ok := body.Attributes[name]; ok {
		return a.SrcRange.Start.Line
	}
	return 0
}

func blockLine(b *hclsyntax.Block) int { return b.DefRange().Start.Line }

func ctyString(v cty.Value) string {
	if v.Type() == cty.String && !v.IsNull() {
		return v.AsString()
	}
	return ""
}

func ctyInt(v cty.Value) int {
	if v.Type() == cty.Number && !v.IsNull() {
		i, _ := v.AsBigFloat().Int64()
		return int(i)
	}
	return 0
}
