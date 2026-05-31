package detectors

import (
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Terraform detects cryptographic key material declared in HCL. HCL has no
// stdlib parser and the project keeps a zero-dependency bias, so this is a
// precision-first regex detector over crypto resource blocks rather than a full
// HCL parse: it reads only well-known attributes and emits one asset per
// resource, leaving risk to the central classifier.
type Terraform struct{}

func NewTerraform() *Terraform { return &Terraform{} }

func (t *Terraform) Name() string { return "terraform" }

func (t *Terraform) Wants(path string) bool { return filepath.Ext(path) == ".tf" }

var (
	reResourceHeader = regexp.MustCompile(`(?m)resource\s+"([a-z0-9_]+)"\s+"[^"]*"\s*\{`)
	reAttrString     = func(name string) *regexp.Regexp {
		return regexp.MustCompile(name + `\s*=\s*"([^"]*)"`)
	}
	reAttrInt = func(name string) *regexp.Regexp {
		return regexp.MustCompile(name + `\s*=\s*(\d+)`)
	}
	reKMSSpec      = reAttrString("customer_master_key_spec")
	reAlgorithm    = reAttrString("algorithm")
	reRSABits      = reAttrInt("rsa_bits")
	reKeyType      = reAttrString("key_type")
	reKeySize      = reAttrInt("key_size")
	reKMSRSASize   = regexp.MustCompile(`^RSA_(\d+)$`)
	reECCSpecValue = regexp.MustCompile(`^ECC_`)
	reHMACSpec     = regexp.MustCompile(`^HMAC_`)
)

func (t *Terraform) Detect(f scan.File) []model.Finding {
	content := string(f.Content)
	var out []model.Finding
	for _, b := range tfResources(content) {
		switch b.kind {
		case "tls_private_key":
			out = appendIf(out, t.tlsPrivateKey(f, b))
		case "aws_kms_key":
			out = appendIf(out, t.awsKMSKey(f, b))
		case "azurerm_key_vault_key":
			out = appendIf(out, t.azureKey(f, b))
		}
	}
	return out
}

func (t *Terraform) tlsPrivateKey(f scan.File, b tfBlock) *model.Finding {
	algo := "RSA"
	if m := reAlgorithm.FindStringSubmatch(b.body); m != nil {
		algo = m[1]
	}
	switch algo {
	case "RSA":
		size := 2048
		ev := `algorithm = "RSA"`
		if m := reRSABits.FindStringSubmatchIndex(b.body); m != nil {
			size, _ = strconv.Atoi(b.body[m[2]:m[3]])
			ev = b.body[m[0]:m[1]]
			return t.key(f, b, m[0], "RSA", size, model.PrimitiveSignature, ev)
		}
		return t.key(f, b, 0, "RSA", size, model.PrimitiveSignature, ev)
	case "ECDSA":
		return t.key(f, b, 0, "ECDSA", 0, model.PrimitiveSignature, `algorithm = "ECDSA"`)
	}
	return nil
}

func (t *Terraform) awsKMSKey(f scan.File, b tfBlock) *model.Finding {
	spec := "SYMMETRIC_DEFAULT"
	off := 0
	if m := reKMSSpec.FindStringSubmatchIndex(b.body); m != nil {
		spec = b.body[m[2]:m[3]]
		off = m[0]
	}
	ev := "customer_master_key_spec = " + strconv.Quote(spec)
	switch {
	case reKMSRSASize.MatchString(spec):
		size, _ := strconv.Atoi(reKMSRSASize.FindStringSubmatch(spec)[1])
		return t.key(f, b, off, "RSA", size, model.PrimitiveSignature, ev)
	case reECCSpecValue.MatchString(spec):
		return t.key(f, b, off, "ECDSA", 0, model.PrimitiveSignature, ev)
	case reHMACSpec.MatchString(spec):
		return t.key(f, b, off, "HMAC", 0, model.PrimitiveUnknown, ev)
	default: // SYMMETRIC_DEFAULT
		return t.key(f, b, off, "AES", 256, model.PrimitiveEncryption, ev)
	}
}

func (t *Terraform) azureKey(f scan.File, b tfBlock) *model.Finding {
	m := reKeyType.FindStringSubmatchIndex(b.body)
	if m == nil {
		return nil
	}
	kt := b.body[m[2]:m[3]]
	ev := "key_type = " + strconv.Quote(kt)
	switch kt {
	case "RSA", "RSA-HSM":
		size := 2048
		if s := reKeySize.FindStringSubmatch(b.body); s != nil {
			size, _ = strconv.Atoi(s[1])
		}
		return t.key(f, b, m[0], "RSA", size, model.PrimitiveSignature, ev)
	case "EC", "EC-HSM":
		return t.key(f, b, m[0], "ECDSA", 0, model.PrimitiveSignature, ev)
	case "oct", "oct-HSM":
		return t.key(f, b, m[0], "AES", 0, model.PrimitiveEncryption, ev)
	}
	return nil
}

// key builds a finding for an asset at bodyOffset within the block body.
func (t *Terraform) key(f scan.File, b tfBlock, bodyOffset int, algo string, size int, prim model.Primitive, ev string) *model.Finding {
	return &model.Finding{
		Asset:    model.Asset{Type: model.TypeKey, Algorithm: algo, KeySize: size, Primitive: prim},
		Location: model.Location{File: f.Path, Line: lineNumber(f.Content, b.bodyStart+bodyOffset)},
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

// tfBlock is a resource block: its resource type, body text and the byte offset
// of the body within the original file.
type tfBlock struct {
	kind      string
	body      string
	bodyStart int
}

// tfResources extracts top-level resource blocks via brace matching that skips
// strings and comments, so braces inside them do not unbalance the scan.
func tfResources(content string) []tfBlock {
	var blocks []tfBlock
	for _, h := range reResourceHeader.FindAllStringSubmatchIndex(content, -1) {
		bodyStart := h[1] // just past the opening "{"
		end, ok := matchBrace(content, bodyStart)
		if !ok {
			continue
		}
		blocks = append(blocks, tfBlock{
			kind:      content[h[2]:h[3]],
			body:      content[bodyStart:end],
			bodyStart: bodyStart,
		})
	}
	return blocks
}

// matchBrace returns the index of the closing brace that balances the opening
// brace immediately before start, skipping string literals and comments.
func matchBrace(s string, start int) (int, bool) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '"':
			i = skipString(s, i)
		case '#':
			i = skipLine(s, i)
		case '/':
			if i+1 < len(s) && s[i+1] == '/' {
				i = skipLine(s, i)
			} else if i+1 < len(s) && s[i+1] == '*' {
				i = skipBlockComment(s, i)
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func skipString(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == '"' {
			return j
		}
	}
	return len(s)
}

func skipLine(s string, i int) int {
	for j := i; j < len(s); j++ {
		if s[j] == '\n' {
			return j
		}
	}
	return len(s)
}

func skipBlockComment(s string, i int) int {
	for j := i + 2; j+1 < len(s); j++ {
		if s[j] == '*' && s[j+1] == '/' {
			return j + 1
		}
	}
	return len(s)
}
