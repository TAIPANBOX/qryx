// Package azure is a cloud connector that inventories cryptographic keys in an
// Azure Key Vault. It produces model.Finding values for the shared
// graph/report/store path and hides the SDK behind a small lister interface so
// the mapping logic is testable without live Azure credentials.
package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// keyItem is the minimal per-key metadata the lister exposes.
type keyItem struct {
	ID      string
	Name    string
	Version string
	Attrs   *azkeys.KeyAttributes
}

// keyLister is the test seam: the real implementation pages the SDK, fakes
// return canned slices.
type keyLister interface {
	list(ctx context.Context) ([]keyItem, error)
	getKey(ctx context.Context, name, version string) (*azkeys.JSONWebKey, error)
}

// Scan inventories the Key Vault at vaultURL using DefaultAzureCredential.
func Scan(ctx context.Context, vaultURL string) ([]model.Finding, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure keyvault client: %w", err)
	}
	return scanWith(ctx, azureLister{client})
}

// scanWith is the testable core.
func scanWith(ctx context.Context, l keyLister) ([]model.Finding, error) {
	items, err := l.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, item := range items {
		// Skip disabled keys.
		if item.Attrs != nil && item.Attrs.Enabled != nil && !*item.Attrs.Enabled {
			continue
		}

		jwk, err := l.getKey(ctx, item.Name, item.Version)
		if err != nil {
			return nil, err
		}

		kty := azkeys.KeyTypeEC // default; overwritten below
		if jwk != nil && jwk.Kty != nil {
			kty = *jwk.Kty
		}
		var nBytes []byte
		if jwk != nil {
			nBytes = jwk.N
		}

		asset, ok := keyTypeToAsset(kty, nBytes)
		if !ok {
			continue
		}
		out = append(out, model.Finding{
			Asset:    asset,
			Location: model.Location{File: item.ID},
			Evidence: fmt.Sprintf("Key Vault key %s type %s", item.Name, kty),
			Source:   "azure-keyvault",
		})

		// Expired key is an additional context-risk finding.
		if item.Attrs != nil && item.Attrs.Expires != nil && item.Attrs.Expires.Before(time.Now()) {
			out = append(out, model.Finding{
				Asset:    asset,
				Location: model.Location{File: item.ID},
				Evidence: fmt.Sprintf("Key Vault key %s expired %s", item.Name, item.Attrs.Expires.Format("2006-01-02")),
				Source:   "azure-keyvault",
				Risk: model.Risk{
					Class:    model.RiskExpired,
					Severity: model.SeverityHigh,
					Reason:   "key is past its expiry date",
				},
			})
		}
	}
	return out, nil
}

// azureLister is the real SDK-backed implementation.
type azureLister struct {
	client *azkeys.Client
}

func (a azureLister) list(ctx context.Context) ([]keyItem, error) {
	var out []keyItem
	pager := a.client.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, kp := range page.Value {
			if kp == nil || kp.KID == nil {
				continue
			}
			out = append(out, keyItem{
				ID:      string(*kp.KID),
				Name:    kp.KID.Name(),
				Version: kp.KID.Version(),
				Attrs:   kp.Attributes,
			})
		}
	}
	return out, nil
}

func (a azureLister) getKey(ctx context.Context, name, version string) (*azkeys.JSONWebKey, error) {
	resp, err := a.client.GetKey(ctx, name, version, nil)
	if err != nil {
		return nil, err
	}
	if resp.Key == nil {
		return nil, nil
	}
	return resp.Key, nil
}

// keyTypeToAsset maps an Azure JSON Web Key type to a qryx asset. n is the RSA
// modulus bytes used to derive the key size; it may be nil.
func keyTypeToAsset(kty azkeys.KeyType, n []byte) (model.Asset, bool) {
	switch kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		return model.Asset{Type: model.TypeKey, Algorithm: "ECDSA", Primitive: model.PrimitiveSignature}, true
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		size := len(n) * 8 // RSA modulus length in bits
		return model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: size, Primitive: model.PrimitiveSignature}, true
	case azkeys.KeyTypeOct, azkeys.KeyTypeOctHSM:
		// AES key size cannot be derived from public metadata for symmetric keys.
		return model.Asset{Type: model.TypeKey, Algorithm: "AES", Primitive: model.PrimitiveEncryption}, true
	default:
		return model.Asset{}, false
	}
}
