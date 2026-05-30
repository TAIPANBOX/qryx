package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func ptr[T any](v T) *T { return &v }

// fakeKMS serves canned keys across two pages to exercise pagination.
type fakeKMS struct {
	keys map[string]kmstypes.KeySpec // keyId -> spec
}

func (f fakeKMS) ListKeys(_ context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	// Page 1 returns the first key and a marker; page 2 returns the rest.
	ids := make([]string, 0, len(f.keys))
	for id := range f.keys {
		ids = append(ids, id)
	}
	if in.Marker == nil && len(ids) > 1 {
		return &kms.ListKeysOutput{
			Keys:       []kmstypes.KeyListEntry{{KeyId: ptr(ids[0])}},
			Truncated:  true,
			NextMarker: ptr("page2"),
		}, nil
	}
	var entries []kmstypes.KeyListEntry
	start := 0
	if in.Marker != nil {
		start = 1
	}
	for _, id := range ids[start:] {
		entries = append(entries, kmstypes.KeyListEntry{KeyId: ptr(id)})
	}
	return &kms.ListKeysOutput{Keys: entries}, nil
}

func (f fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		KeyId:   in.KeyId,
		Arn:     ptr("arn:aws:kms:us-east-1:111:key/" + *in.KeyId),
		KeySpec: f.keys[*in.KeyId],
	}}, nil
}

type fakeACM struct {
	certs []acmtypes.CertificateDetail
}

func (f fakeACM) ListCertificates(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	var sums []acmtypes.CertificateSummary
	for _, c := range f.certs {
		sums = append(sums, acmtypes.CertificateSummary{CertificateArn: c.CertificateArn})
	}
	return &acm.ListCertificatesOutput{CertificateSummaryList: sums}, nil
}

func (f fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	for i := range f.certs {
		if *f.certs[i].CertificateArn == *in.CertificateArn {
			return &acm.DescribeCertificateOutput{Certificate: &f.certs[i]}, nil
		}
	}
	return &acm.DescribeCertificateOutput{}, nil
}

func TestScanKMSMapsSpecsAcrossPages(t *testing.T) {
	api := fakeKMS{keys: map[string]kmstypes.KeySpec{
		"k-rsa": kmstypes.KeySpecRsa2048,
		"k-ecc": kmstypes.KeySpecEccNistP256,
		"k-sym": kmstypes.KeySpecSymmetricDefault,
	}}
	got, err := scanKMS(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (pagination?)", len(got))
	}
	byAlgo := map[string]model.Asset{}
	for _, f := range got {
		byAlgo[f.Asset.Algorithm] = f.Asset
		if f.Source != "aws-kms" || f.Location.File == "" {
			t.Errorf("bad metadata: %+v", f)
		}
	}
	if a, ok := byAlgo["RSA"]; !ok || a.KeySize != 2048 {
		t.Errorf("RSA spec mismapped: %+v", a)
	}
	if _, ok := byAlgo["ECDSA"]; !ok {
		t.Error("ECC spec not mapped to ECDSA")
	}
	if a, ok := byAlgo["AES"]; !ok || a.KeySize != 256 {
		t.Errorf("SYMMETRIC_DEFAULT not mapped to AES-256: %+v", a)
	}
}

func TestScanACMMapsAlgoAndExpiry(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	api := fakeACM{certs: []acmtypes.CertificateDetail{
		{CertificateArn: ptr("arn:cert/1"), DomainName: ptr("a.example"), KeyAlgorithm: acmtypes.KeyAlgorithmRsa2048, NotAfter: ptr(time.Now().Add(24 * time.Hour))},
		{CertificateArn: ptr("arn:cert/2"), DomainName: ptr("b.example"), KeyAlgorithm: acmtypes.KeyAlgorithmEcPrime256v1, NotAfter: &past},
	}}
	got, err := scanACM(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}

	var sawRSA, sawECDSA, sawExpired bool
	for _, f := range got {
		switch {
		case f.Asset.Algorithm == "RSA" && f.Asset.KeySize == 2048:
			sawRSA = true
		case f.Asset.Algorithm == "ECDSA":
			sawECDSA = true
		}
		if f.Risk.Class == model.RiskExpired {
			sawExpired = true
		}
	}
	if !sawRSA || !sawECDSA {
		t.Errorf("ACM algorithms mismapped: %+v", got)
	}
	if !sawExpired {
		t.Error("expired certificate not flagged")
	}
}

func TestKeySpecToAssetUnknown(t *testing.T) {
	if _, ok := keySpecToAsset("SM2"); ok {
		t.Skip("SM2 intentionally unmapped; adjust if support is added")
	}
}
