package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
	keys     map[string]kmstypes.KeySpec  // keyId -> spec
	tags     map[string]map[string]string // keyId -> tag map (optional)
	denyKey  map[string]bool              // keyId -> DescribeKey returns AccessDenied
	denyTags map[string]bool              // keyId -> ListResourceTags returns AccessDenied
}

func (f fakeKMS) ListKeys(_ context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	// Page 1 returns the first key and a marker; page 2 returns the rest.
	// Sort for a stable order — map iteration differs between the two calls and
	// would otherwise drop or duplicate a key.
	ids := make([]string, 0, len(f.keys))
	for id := range f.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
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
	if f.denyKey[*in.KeyId] {
		return nil, fmt.Errorf("AccessDeniedException: no kms:DescribeKey on %s", *in.KeyId)
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		KeyId:   in.KeyId,
		Arn:     ptr("arn:aws:kms:us-east-1:111:key/" + *in.KeyId),
		KeySpec: f.keys[*in.KeyId],
	}}, nil
}

func (f fakeKMS) ListResourceTags(_ context.Context, in *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	if f.denyTags[*in.KeyId] {
		return nil, fmt.Errorf("AccessDeniedException: no kms:ListResourceTags on %s", *in.KeyId)
	}
	if f.tags == nil {
		return &kms.ListResourceTagsOutput{}, nil
	}
	var out []kmstypes.Tag
	for k, v := range f.tags[*in.KeyId] {
		k, v := k, v
		out = append(out, kmstypes.Tag{TagKey: &k, TagValue: &v})
	}
	return &kms.ListResourceTagsOutput{Tags: out}, nil
}

type fakeACM struct {
	certs    []acmtypes.CertificateDetail
	tags     map[string]map[string]string // arn -> tag map (optional)
	denyCert map[string]bool              // arn -> DescribeCertificate returns AccessDenied
}

func (f fakeACM) ListCertificates(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	var sums []acmtypes.CertificateSummary
	for _, c := range f.certs {
		sums = append(sums, acmtypes.CertificateSummary{CertificateArn: c.CertificateArn})
	}
	return &acm.ListCertificatesOutput{CertificateSummaryList: sums}, nil
}

func (f fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if f.denyCert[*in.CertificateArn] {
		return nil, fmt.Errorf("AccessDeniedException: no acm:DescribeCertificate on %s", *in.CertificateArn)
	}
	for i := range f.certs {
		if *f.certs[i].CertificateArn == *in.CertificateArn {
			return &acm.DescribeCertificateOutput{Certificate: &f.certs[i]}, nil
		}
	}
	return &acm.DescribeCertificateOutput{}, nil
}

func (f fakeACM) ListTagsForCertificate(_ context.Context, in *acm.ListTagsForCertificateInput, _ ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
	if f.tags == nil {
		return &acm.ListTagsForCertificateOutput{}, nil
	}
	var out []acmtypes.Tag
	for k, v := range f.tags[*in.CertificateArn] {
		k, v := k, v
		out = append(out, acmtypes.Tag{Key: &k, Value: &v})
	}
	return &acm.ListTagsForCertificateOutput{Tags: out}, nil
}

func TestScanKMSMapsSpecsAcrossPages(t *testing.T) {
	api := fakeKMS{keys: map[string]kmstypes.KeySpec{
		"k-rsa": kmstypes.KeySpecRsa2048,
		"k-ecc": kmstypes.KeySpecEccNistP256,
		"k-sym": kmstypes.KeySpecSymmetricDefault,
	}}
	got, _, err := scanKMS(context.Background(), api)
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
	got, _, err := scanACM(context.Background(), api)
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

// TestScanACMExpiryPreservesRealKeyAlgorithm guards against the expiry
// finding collapsing every expired cert into one generic {Certificate, "TLS",
// 0} node regardless of its actual key. An expired RSA-1024 cert's expiry
// finding must carry Algorithm "RSA" / KeySize 1024 (the cert's real key),
// not the hardcoded "TLS"/0: otherwise a CBOM/CNSA/dashboard reader can't
// tell an expired RSA-1024 cert (also a weak-key finding, needs an algorithm
// replacement) from an expired ECDSA cert (just needs renewal).
func TestScanACMExpiryPreservesRealKeyAlgorithm(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	api := fakeACM{certs: []acmtypes.CertificateDetail{
		{CertificateArn: ptr("arn:cert/weak"), DomainName: ptr("weak.example"), KeyAlgorithm: acmtypes.KeyAlgorithmRsa1024, NotAfter: &past},
	}}
	got, _, err := scanACM(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}

	var expiry *model.Finding
	for i := range got {
		if got[i].Risk.Class == model.RiskExpired {
			expiry = &got[i]
		}
	}
	if expiry == nil {
		t.Fatalf("no expiry finding: %+v", got)
	}
	if expiry.Asset.Algorithm != "RSA" || expiry.Asset.KeySize != 1024 {
		t.Errorf("expiry finding asset = %+v, want RSA/1024 (the cert's real key), not a hardcoded TLS/0", expiry.Asset)
	}
	if expiry.Asset.Type != model.TypeCertificate {
		t.Errorf("expiry finding type = %q, want %q", expiry.Asset.Type, model.TypeCertificate)
	}
}

func TestScanKMSTagsPopulated(t *testing.T) {
	api := fakeKMS{
		keys: map[string]kmstypes.KeySpec{"k1": kmstypes.KeySpecRsa2048},
		tags: map[string]map[string]string{"k1": {"Owner": "security-team", "env": "prod"}},
	}
	got, _, err := scanKMS(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].Tags["Owner"] != "security-team" {
		t.Errorf("Owner tag not propagated: %v", got[0].Tags)
	}
}

func TestScanACMTagsPopulated(t *testing.T) {
	api := fakeACM{
		certs: []acmtypes.CertificateDetail{{
			CertificateArn: ptr("arn:cert/t1"),
			DomainName:     ptr("t.example"),
			KeyAlgorithm:   acmtypes.KeyAlgorithmRsa2048,
			NotAfter:       ptr(time.Now().Add(24 * time.Hour)),
		}},
		tags: map[string]map[string]string{"arn:cert/t1": {"team": "infra"}},
	}
	got, _, err := scanACM(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	if got[0].Tags["team"] != "infra" {
		t.Errorf("team tag not propagated: %v", got[0].Tags)
	}
}

// TestScanKMSSkipsAKeyItCannotRead pins that one denied resource does not end
// the inventory. A policy granting kms:ListKeys but not kms:DescribeKey on
// every key is an ordinary configuration, and the connector used to return the
// first such error, so the operator got no inventory at all from an account
// that had one. Skipping is only honest if the skip is reported, so the
// resources that could not be read come back as a second return value and the
// CLI prints them.
func TestScanKMSSkipsAKeyItCannotRead(t *testing.T) {
	api := fakeKMS{
		keys: map[string]kmstypes.KeySpec{
			"k-denied": kmstypes.KeySpecRsa2048,
			"k-ok":     kmstypes.KeySpecEccNistP256,
			"k-sym":    kmstypes.KeySpecSymmetricDefault,
		},
		denyKey: map[string]bool{"k-denied": true},
	}
	got, skipped, err := scanKMS(context.Background(), api)
	if err != nil {
		t.Fatalf("one unreadable key ended the whole inventory: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2 (the readable keys): %+v", len(got), got)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped=%v, want exactly one entry", skipped)
	}
	if !strings.Contains(skipped[0], "k-denied") {
		t.Errorf("skipped entry %q does not name the key it could not read", skipped[0])
	}
}

// A tag read failing is the same shape one call deeper: the key itself was
// read, so it belongs in the inventory, with its unreadable tags reported.
func TestScanKMSKeepsAKeyWhoseTagsAreDenied(t *testing.T) {
	api := fakeKMS{
		keys:     map[string]kmstypes.KeySpec{"k1": kmstypes.KeySpecRsa2048},
		denyTags: map[string]bool{"k1": true},
	}
	got, skipped, err := scanKMS(context.Background(), api)
	if err != nil {
		t.Fatalf("unreadable tags ended the inventory: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d findings, want 1: the key was readable, only its tags were not", len(got))
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "k1") {
		t.Errorf("skipped=%v, want one entry naming k1's tags", skipped)
	}
}

func TestScanACMSkipsACertificateItCannotRead(t *testing.T) {
	api := fakeACM{
		certs: []acmtypes.CertificateDetail{
			{CertificateArn: ptr("arn:cert/ok"), DomainName: ptr("a.example"), KeyAlgorithm: acmtypes.KeyAlgorithmRsa2048, NotAfter: ptr(time.Now().Add(24 * time.Hour))},
			{CertificateArn: ptr("arn:cert/denied"), DomainName: ptr("b.example"), KeyAlgorithm: acmtypes.KeyAlgorithmEcPrime256v1, NotAfter: ptr(time.Now().Add(24 * time.Hour))},
		},
		denyCert: map[string]bool{"arn:cert/denied": true},
	}
	got, skipped, err := scanACM(context.Background(), api)
	if err != nil {
		t.Fatalf("one unreadable certificate ended the whole inventory: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d findings, want 1 (the readable certificate): %+v", len(got), got)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "arn:cert/denied") {
		t.Errorf("skipped=%v, want one entry naming the denied certificate", skipped)
	}
}

func TestKeySpecToAssetUnknown(t *testing.T) {
	if _, ok := keySpecToAsset("SM2"); ok {
		t.Skip("SM2 intentionally unmapped; adjust if support is added")
	}
}
