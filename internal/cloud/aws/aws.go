// Package aws is a cloud connector that inventories cryptographic material in an
// AWS account: KMS keys and ACM certificates. Like the other connectors it
// produces model.Finding values that flow into the shared graph/report/store
// path. SDK access sits behind small interfaces so the collection logic is
// testable without a live account.
package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// kmsAPI is the subset of the KMS client the connector uses (the test seam).
type kmsAPI interface {
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
}

// acmAPI is the subset of the ACM client the connector uses (the test seam).
type acmAPI interface {
	ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	ListTagsForCertificate(context.Context, *acm.ListTagsForCertificateInput, ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error)
}

// Scan inventories KMS keys and ACM certificates in the given region using the
// default AWS credential chain (optionally a named shared-config profile).
func Scan(ctx context.Context, region, profile string) ([]model.Finding, error) {
	opts := []func(*config.LoadOptions) error{}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var out []model.Finding
	kmsFindings, err := scanKMS(ctx, kms.NewFromConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	out = append(out, kmsFindings...)

	acmFindings, err := scanACM(ctx, acm.NewFromConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("acm: %w", err)
	}
	return append(out, acmFindings...), nil
}

func scanKMS(ctx context.Context, api kmsAPI) ([]model.Finding, error) {
	var out []model.Finding
	var marker *string
	for {
		page, err := api.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Keys {
			if entry.KeyId == nil {
				continue
			}
			desc, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyId})
			if err != nil {
				return nil, err
			}
			meta := desc.KeyMetadata
			if meta == nil {
				continue
			}
			asset, ok := keySpecToAsset(string(meta.KeySpec))
			if !ok {
				continue
			}
			tags, err := fetchKMSTags(ctx, api, entry.KeyId)
			if err != nil {
				return nil, err
			}
			out = append(out, model.Finding{
				Asset:    asset,
				Location: model.Location{File: deref(meta.Arn, deref(meta.KeyId, ""))},
				Evidence: "KMS key spec " + string(meta.KeySpec),
				Source:   "aws-kms",
				Tags:     tags,
			})
		}
		if page.Truncated && page.NextMarker != nil {
			marker = page.NextMarker
			continue
		}
		return out, nil
	}
}

func fetchKMSTags(ctx context.Context, api kmsAPI, keyID *string) (map[string]string, error) {
	resp, err := api.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: keyID})
	if err != nil {
		return nil, err
	}
	if len(resp.Tags) == 0 {
		return nil, nil
	}
	tags := make(map[string]string, len(resp.Tags))
	for _, t := range resp.Tags {
		if t.TagKey != nil && t.TagValue != nil {
			tags[*t.TagKey] = *t.TagValue
		}
	}
	return tags, nil
}

func scanACM(ctx context.Context, api acmAPI) ([]model.Finding, error) {
	var out []model.Finding
	var token *string
	for {
		page, err := api.ListCertificates(ctx, &acm.ListCertificatesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, sum := range page.CertificateSummaryList {
			if sum.CertificateArn == nil {
				continue
			}
			desc, err := api.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: sum.CertificateArn})
			if err != nil {
				return nil, err
			}
			cert := desc.Certificate
			if cert == nil {
				continue
			}
			arn := deref(cert.CertificateArn, "")
			tags, err := fetchACMTags(ctx, api, cert.CertificateArn)
			if err != nil {
				return nil, err
			}
			asset, ok := acmKeyAlgoToAsset(string(cert.KeyAlgorithm))
			if ok {
				out = append(out, model.Finding{
					Asset:    asset,
					Location: model.Location{File: arn},
					Evidence: fmt.Sprintf("ACM certificate %s, %s", deref(cert.DomainName, ""), cert.KeyAlgorithm),
					Source:   "aws-acm",
					Tags:     tags,
				})
			}
			if cert.NotAfter != nil && cert.NotAfter.Before(time.Now()) {
				// Reuse the cert's real key algorithm/size on the expiry finding
				// too (mirroring azure.go), so an expired RSA-1024 cert and an
				// expired ECDSA cert don't collapse into one generic "TLS" node
				// that hides which one also needs an algorithm/size fix, not
				// just renewal. Type stays TypeCertificate even in the (today
				// unreachable, since every real ACM KeyAlgorithm is RSA_*/EC_*)
				// case the algorithm itself isn't recognized.
				expired := asset
				expired.Type = model.TypeCertificate
				out = append(out, model.Finding{
					Asset:    expired,
					Location: model.Location{File: arn},
					Evidence: fmt.Sprintf("ACM certificate %s expired %s", deref(cert.DomainName, ""), cert.NotAfter.Format("2006-01-02")),
					Source:   "aws-acm",
					Risk:     model.Risk{Class: model.RiskExpired, Severity: model.SeverityHigh, Reason: "certificate is past its NotAfter date"},
					Tags:     tags,
				})
			}
		}
		if page.NextToken != nil {
			token = page.NextToken
			continue
		}
		return out, nil
	}
}

func fetchACMTags(ctx context.Context, api acmAPI, arn *string) (map[string]string, error) {
	resp, err := api.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{CertificateArn: arn})
	if err != nil {
		return nil, err
	}
	if len(resp.Tags) == 0 {
		return nil, nil
	}
	tags := make(map[string]string, len(resp.Tags))
	for _, t := range resp.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

// keySpecToAsset maps a KMS KeySpec to an asset. ok is false for specs that are
// not cryptographic assets we track.
func keySpecToAsset(spec string) (model.Asset, bool) {
	switch {
	case strings.HasPrefix(spec, "RSA_"):
		return model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: atoi(strings.TrimPrefix(spec, "RSA_")), Primitive: model.PrimitiveSignature}, true
	case strings.HasPrefix(spec, "ECC_"):
		return model.Asset{Type: model.TypeKey, Algorithm: "ECDSA", Primitive: model.PrimitiveSignature}, true
	case spec == "SYMMETRIC_DEFAULT":
		return model.Asset{Type: model.TypeKey, Algorithm: "AES", KeySize: 256, Primitive: model.PrimitiveEncryption}, true
	case strings.HasPrefix(spec, "HMAC_"):
		return model.Asset{Type: model.TypeKey, Algorithm: "HMAC", Primitive: model.PrimitiveHash}, true
	default:
		return model.Asset{}, false
	}
}

// acmKeyAlgoToAsset maps an ACM KeyAlgorithm to an asset.
func acmKeyAlgoToAsset(algo string) (model.Asset, bool) {
	switch {
	case strings.HasPrefix(algo, "RSA_"):
		return model.Asset{Type: model.TypeCertificate, Algorithm: "RSA", KeySize: atoi(strings.TrimPrefix(algo, "RSA_")), Primitive: model.PrimitiveSignature}, true
	case strings.HasPrefix(algo, "EC_"):
		return model.Asset{Type: model.TypeCertificate, Algorithm: "ECDSA", Primitive: model.PrimitiveSignature}, true
	default:
		return model.Asset{}, false
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func deref(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}
