package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// CBOM emits a CycloneDX 1.6 Bill of Materials with cryptographic-asset
// components. The schema is large; Phase 0 emits the subset consumers need:
// metadata, components with cryptoProperties, and qryx risk as properties.
type cbomDoc struct {
	BOMFormat   string       `json:"bomFormat"`
	SpecVersion string       `json:"specVersion"`
	Version     int          `json:"version"`
	Metadata    cbomMetadata `json:"metadata"`
	Components  []cbomComp   `json:"components"`
}

type cbomMetadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []cbomTool `json:"tools"`
	Component cbomComp   `json:"component"`
}

type cbomTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cbomComp struct {
	Type             string         `json:"type"`
	BOMRef           string         `json:"bom-ref,omitempty"`
	Name             string         `json:"name"`
	CryptoProperties *cryptoProps   `json:"cryptoProperties,omitempty"`
	Evidence         *cbomEvidence  `json:"evidence,omitempty"`
	Properties       []cbomProperty `json:"properties,omitempty"`
}

type cryptoProps struct {
	AssetType      string                `json:"assetType"`
	AlgorithmProps *algorithmProps       `json:"algorithmProperties,omitempty"`
	ProtocolProps  *protocolProps        `json:"protocolProperties,omitempty"`
	RelatedProps   *relatedMaterialProps `json:"relatedCryptoMaterialProperties,omitempty"`
}

// protocolProps is CycloneDX 1.6's protocolProperties, the part this writer
// fills: the protocol type (tls, ssh, ...).
type protocolProps struct {
	Type string `json:"type"`
}

// relatedMaterialProps is CycloneDX 1.6's relatedCryptoMaterialProperties,
// the part this writer fills: what kind of key material was found.
type relatedMaterialProps struct {
	Type string `json:"type"`
}

type algorithmProps struct {
	Primitive      string `json:"primitive,omitempty"`
	ParameterSetID string `json:"parameterSetIdentifier,omitempty"`
}

type cbomEvidence struct {
	Occurrences []cbomOccurrence `json:"occurrences"`
}

type cbomOccurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

type cbomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CBOM writes the scan result as CycloneDX JSON to w.
func CBOM(w io.Writer, res *scan.Result, version string) error {
	doc := cbomDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cbomMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cbomTool{
				{Vendor: "qryx", Name: "qryx", Version: version},
			},
			Component: cbomComp{
				Type: "application",
				Name: res.Root,
			},
		},
	}

	for _, node := range graph.Build(res.Findings) {
		// A CBOM is specifically a Cryptography Bill of Materials: every
		// component here is typed "cryptographic-asset" below. A
		// non-cryptographic inventory fact (e.g. an ai-usage finding) would
		// misrepresent the document if it rode along, so it is excluded
		// rather than mislabeled. See model.AssetType.IsCryptographic.
		if !node.Asset.Type.IsCryptographic() {
			continue
		}
		doc.Components = append(doc.Components, toComponent(node))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// toComponent renders one asset node as a single CycloneDX component carrying
// every occurrence of that asset: the graph, not a flat per-finding dump.
func toComponent(n graph.AssetNode) cbomComp {
	name := n.Asset.Algorithm
	if n.Asset.KeySize > 0 {
		name = fmt.Sprintf("%s-%d", name, n.Asset.KeySize)
	}

	occ := make([]cbomOccurrence, 0, len(n.Occurrences))
	sources := map[string]bool{}
	for _, o := range n.Occurrences {
		occ = append(occ, cbomOccurrence{Location: o.Location.File, Line: o.Location.Line})
		if o.Source != "" {
			sources[o.Source] = true
		}
	}

	// The CycloneDX 1.6 boundary (cbom_vocab.go): the internal asset type and
	// primitive are wider than the spec's enums and are mapped here, never
	// copied. A library is not a cryptographic asset to the spec at all; it is
	// a `library` component carrying the same evidence and qryx properties.
	comp := cbomComp{
		Type:     "cryptographic-asset",
		BOMRef:   bomRef(n),
		Name:     name,
		Evidence: &cbomEvidence{Occurrences: occ},
		Properties: []cbomProperty{
			{Name: "qryx:detectors", Value: joinSorted(sources)},
			{Name: "qryx:risk", Value: string(n.Risk.Class)},
			{Name: "qryx:severity", Value: n.Risk.Severity.String()},
			{Name: "qryx:occurrences", Value: fmt.Sprintf("%d", len(n.Occurrences))},
		},
	}
	if n.Risk.Reason != "" {
		comp.Properties = append(comp.Properties,
			cbomProperty{Name: "qryx:reason", Value: n.Risk.Reason})
	}
	switch n.Asset.Type {
	case model.TypeLibrary:
		comp.Type = "library"
	case model.TypeProtocol:
		comp.CryptoProperties = &cryptoProps{
			AssetType:     "protocol",
			ProtocolProps: &protocolProps{Type: cdxProtocolType(n.Asset.Algorithm)},
		}
	case model.TypeKey:
		comp.CryptoProperties = &cryptoProps{
			AssetType:    "related-crypto-material",
			RelatedProps: &relatedMaterialProps{Type: cdxKeyMaterialType(n.Asset.Algorithm)},
		}
	default: // algorithm and certificate
		assetType := "algorithm"
		if n.Asset.Type == model.TypeCertificate {
			assetType = "certificate"
		}
		comp.CryptoProperties = &cryptoProps{
			AssetType: assetType,
			AlgorithmProps: &algorithmProps{
				Primitive: cdxPrimitive(n.Asset.Algorithm, n.Asset.Primitive),
			},
		}
		if n.Asset.KeySize > 0 {
			comp.CryptoProperties.AlgorithmProps.ParameterSetID = fmt.Sprintf("%d", n.Asset.KeySize)
		}
	}
	return comp
}

// bomRef is a stable identifier for an asset node, derived from its canonical
// identity (type, algorithm, key size, risk class) so it is reproducible
// across runs. Risk class must be part of the hash, mirroring
// graph.AssetKey: graph.Build keys AssetNode on risk class too (see
// internal/graph/graph.go), so the same physical asset carrying two
// orthogonal risks (e.g. a certificate that is both quantum-vulnerable and
// expired) produces two AssetNodes. Without risk class here, both would hash
// to the same bom-ref, and CycloneDX requires bom-ref to be unique within a
// document.
func bomRef(n graph.AssetNode) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s",
		n.Asset.Type, n.Asset.Algorithm, n.Asset.KeySize, n.Risk.Class)))
	return "crypto:" + hex.EncodeToString(h[:8])
}

// joinSorted renders a set of strings as a sorted, comma-separated list.
func joinSorted(set map[string]bool) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
