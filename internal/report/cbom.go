package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

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
	AssetType      string          `json:"assetType"`
	AlgorithmProps *algorithmProps `json:"algorithmProperties,omitempty"`
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

	for _, f := range res.Findings {
		doc.Components = append(doc.Components, toComponent(f))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func toComponent(f model.Finding) cbomComp {
	name := f.Asset.Algorithm
	if f.Asset.KeySize > 0 {
		name = fmt.Sprintf("%s-%d", name, f.Asset.KeySize)
	}

	comp := cbomComp{
		Type:   "cryptographic-asset",
		BOMRef: bomRef(f),
		Name:   name,
		CryptoProperties: &cryptoProps{
			AssetType: string(f.Asset.Type),
			AlgorithmProps: &algorithmProps{
				Primitive: string(f.Asset.Primitive),
			},
		},
		Evidence: &cbomEvidence{
			Occurrences: []cbomOccurrence{
				{Location: f.Location.File, Line: f.Location.Line},
			},
		},
		Properties: []cbomProperty{
			{Name: "qryx:detector", Value: f.Source},
			{Name: "qryx:risk", Value: string(f.Risk.Class)},
			{Name: "qryx:severity", Value: f.Risk.Severity.String()},
		},
	}
	if f.Risk.Reason != "" {
		comp.Properties = append(comp.Properties,
			cbomProperty{Name: "qryx:reason", Value: f.Risk.Reason})
	}
	if f.Asset.KeySize > 0 {
		comp.CryptoProperties.AlgorithmProps.ParameterSetID = fmt.Sprintf("%d", f.Asset.KeySize)
	}
	return comp
}

// bomRef is a stable identifier derived from algorithm and location.
func bomRef(f model.Finding) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s",
		f.Asset.Algorithm, f.Location.File, f.Location.Line, f.Source)))
	return "crypto:" + hex.EncodeToString(h[:8])
}
