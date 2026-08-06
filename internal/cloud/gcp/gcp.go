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

// keyVersion is a single enabled crypto-key version: its resource name, the
// algorithm enum as a string, and any labels inherited from the parent key.
type keyVersion struct {
	Name      string
	Algorithm string
	Labels    map[string]string // inherited from CryptoKey.Labels
}

// AllLocations is the Cloud KMS wildcard: `projects/<p>/locations/-` lists key
// rings in every location the caller can see, and it is what `qryx gcp` asks
// for unless --location narrows it.
//
// It used to default to "global". Cloud KMS key rings are overwhelmingly
// regional, so a plain `qryx gcp --project X` inventoried one location out of
// dozens, found almost nothing in a real project, and reported that as a clean
// result. The single-location scope was a choice, not an API constraint.
const AllLocations = "-"

// keyLister enumerates enabled KMS key versions in a project/location, and
// names what it could not read (see the AWS connector's Scan for why that is a
// return value rather than an error).
type keyLister interface {
	list(ctx context.Context, project, location string) ([]keyVersion, []string, error)
}

// Scan inventories Cloud KMS key versions using Application Default Credentials.
func Scan(ctx context.Context, project, location string) ([]model.Finding, []string, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()
	return scanWith(ctx, gcpLister{client}, project, location)
}

// scanWith is the testable core: it resolves the scope and maps every version
// the lister returns.
func scanWith(ctx context.Context, l keyLister, project, location string) ([]model.Finding, []string, error) {
	if location == "" {
		location = AllLocations
	}
	versions, skipped, err := l.list(ctx, project, location)
	if err != nil {
		return nil, nil, err
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
			Tags:     v.Labels,
		})
	}
	return out, skipped, nil
}

// gcpLister drains the real KMS iterators (KeyRings → CryptoKeys → versions).
type gcpLister struct {
	client *kms.KeyManagementClient
}

// list drains the real KMS iterators. A failure enumerating one ring's keys,
// or one key's versions, skips that resource and is reported; only the
// top-level ring listing is fatal, since without it there is nothing to walk.
// This matters more now that the default scope is every location: a project
// where one location or one ring is out of reach used to lose the whole
// inventory to it.
//
// Per CLAUDE.md invariant 4, this is the thin real-SDK wiring, and it is the
// part no test covers: the fake in gcp_test.go satisfies keyLister above this
// code, and no account was used. The skip-and-report shape is verified there;
// that these particular iterator errors arrive this way is not.
func (g gcpLister) list(ctx context.Context, project, location string) ([]keyVersion, []string, error) {
	var out []keyVersion
	var skipped []string
	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)
	rings := g.client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
	for {
		ring, err := rings.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		keys := g.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: ring.Name})
		for {
			key, err := keys.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("kms key ring %s: %v", ring.Name, err))
				break
			}
			versions := g.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: key.Name})
			for {
				v, err := versions.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					skipped = append(skipped, fmt.Sprintf("kms key %s: %v", key.Name, err))
					break
				}
				if v.State != kmspb.CryptoKeyVersion_ENABLED {
					continue
				}
				out = append(out, keyVersion{Name: v.Name, Algorithm: v.Algorithm.String(), Labels: key.Labels})
			}
		}
	}
	return out, skipped, nil
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
