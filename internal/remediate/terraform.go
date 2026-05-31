package remediate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// reTFRSABits matches a Terraform rsa_bits attribute assignment. The attribute
// is RSA-specific (tls_private_key), so the match is unambiguous.
var reTFRSABits = regexp.MustCompile(`rsa_bits(\s*=\s*)(\d+)`)

// tfRSABits raises sub-floor rsa_bits values in Terraform. Like rsaKeySize it
// only changes an integer literal, so the result stays valid HCL.
type tfRSABits struct{}

func (tfRSABits) name() string { return "tf-rsa-bits" }

func (tfRSABits) apply(content string, findings []model.Finding, cfg Config) (string, string, bool) {
	if !hasSubFloorTerraformRSA(findings, cfg.MinRSABits) {
		return "", "", false
	}

	type edit struct {
		off, length int
	}
	var edits []edit
	for _, m := range reTFRSABits.FindAllStringSubmatchIndex(content, -1) {
		// m[4],m[5] bound the digits (second capture group).
		bits, err := strconv.Atoi(content[m[4]:m[5]])
		if err != nil || bits >= cfg.MinRSABits {
			continue
		}
		edits = append(edits, edit{off: m[4], length: m[5] - m[4]})
	}
	if len(edits) == 0 {
		return "", "", false
	}

	sort.Slice(edits, func(i, j int) bool { return edits[i].off > edits[j].off })
	out := content
	repl := strconv.Itoa(cfg.MinRSABits)
	for _, e := range edits {
		out = out[:e.off] + repl + out[e.off+e.length:]
	}

	rationale := fmt.Sprintf("raise sub-%d-bit Terraform rsa_bits to %d (CNSA 2.0 interim; migrate to ML-DSA/ML-KEM for PQC)", cfg.MinRSABits, cfg.MinRSABits)
	return out, rationale, true
}

func hasSubFloorTerraformRSA(findings []model.Finding, floor int) bool {
	for _, f := range findings {
		if f.Source == "terraform" && f.Asset.Algorithm == "RSA" && f.Asset.KeySize > 0 && f.Asset.KeySize < floor {
			return true
		}
	}
	return false
}
