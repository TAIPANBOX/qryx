// Package gcp is a cloud connector that inventories cryptographic material in a
// GCP project: Cloud KMS crypto-key versions. Like the AWS connector it produces
// model.Finding values for the shared graph/report/store path, and hides the SDK
// behind a small lister interface so the mapping logic is testable without a
// live project.
package gcp

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// keyVersion is a single enabled crypto-key version: its resource name and the
// algorithm enum as a string. Returning slices (not iterators) is the test seam.
type keyVersion struct {
	Name      string
	Algorithm string
}

// keyLister enumerates enabled KMS key versions in a project/location.
type keyLister interface {
	list(ctx context.Context, project, location string) ([]keyVersion, error)
}

// Scan inventories Cloud KMS key versions using Application Default Credentials.
func Scan(ctx context.Context, project, location string) ([]model.Finding, error) {
	if location == "" {
		location = "global"
	}
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	return scanWith(ctx, gcpLister{client}, project, location)
}

// scanWith is the testable core: it maps every version the lister returns.
func scanWith(ctx context.Context, l keyLister, project, location string) ([]model.Finding, error) {
	versions, err := l.list(ctx, project, location)
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, v := range versions {
		asset, ok := algoToAsset(v.Algorithm)
		if !ok {
			continue
		}
		out = append(out, model.Finding{
			Asset:    asset,
			Location: model.Location{File: v.Name},
			Evidence: "KMS key version algorithm " + v.Algorithm,
			Source:   "gcp-kms",
		})
	}
	return out, nil
}

// gcpLister drains the real KMS iterators (KeyRings → CryptoKeys → versions).
type gcpLister struct {
	client *kms.KeyManagementClient
}

func (g gcpLister) list(ctx context.Context, project, location string) ([]keyVersion, error) {
	var out []keyVersion
	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)
	rings := g.client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
	for {
		ring, err := rings.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		keys := g.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: ring.Name})
		for {
			key, err := keys.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}
			versions := g.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: key.Name})
			for {
				v, err := versions.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return nil, err
				}
				if v.State != kmspb.CryptoKeyVersion_ENABLED {
					continue
				}
				out = append(out, keyVersion{Name: v.Name, Algorithm: v.Algorithm.String()})
			}
		}
	}
	return out, nil
}

var rsaSizeRE = regexp.MustCompile(`_(\d{3,4})_`)

// algoToAsset maps a GCP CryptoKeyVersionAlgorithm enum name to an asset. ok is
// false for algorithms qryx does not track (e.g. UNSPECIFIED, external).
func algoToAsset(algo string) (model.Asset, bool) {
	switch {
	case strings.Contains(algo, "SYMMETRIC"):
		return model.Asset{Type: model.TypeKey, Algorithm: "AES", KeySize: 256, Primitive: model.PrimitiveEncryption}, true
	case strings.HasPrefix(algo, "RSA_"):
		size := 0
		if m := rsaSizeRE.FindStringSubmatch(algo); m != nil {
			size, _ = strconv.Atoi(m[1])
		}
		return model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: size, Primitive: model.PrimitiveSignature}, true
	case strings.HasPrefix(algo, "EC_"):
		return model.Asset{Type: model.TypeKey, Algorithm: "ECDSA", Primitive: model.PrimitiveSignature}, true
	case strings.HasPrefix(algo, "HMAC_"):
		return model.Asset{Type: model.TypeKey, Algorithm: "HMAC", Primitive: model.PrimitiveHash}, true
	case strings.Contains(algo, "ML_DSA"):
		return model.Asset{Type: model.TypeKey, Algorithm: "ML-DSA", Primitive: model.PrimitiveSignature}, true
	case strings.Contains(algo, "ML_KEM"):
		return model.Asset{Type: model.TypeKey, Algorithm: "ML-KEM", Primitive: model.PrimitiveKeyExch}, true
	case strings.Contains(algo, "SLH_DSA"):
		return model.Asset{Type: model.TypeKey, Algorithm: "SLH-DSA", Primitive: model.PrimitiveSignature}, true
	default:
		return model.Asset{}, false
	}
}
