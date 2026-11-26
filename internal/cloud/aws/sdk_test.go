package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeAWS answers the six KMS and ACM JSON-protocol operations the connector
// calls, routed by the X-Amz-Target header the real SDK sends. Anything it does
// not know is a test failure, so a new call the connector starts making cannot
// pass by accident.
type fakeAWS struct {
	t       *testing.T
	failOps map[string]bool
	mu      sync.Mutex
	seen    []string
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := r.Header.Get("X-Amz-Target")
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, op)
	f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		f.t.Errorf("%s: request is not SigV4-signed", op)
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	deny := func() {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"__type":"AccessDeniedException","message":"not allowed"}`)
	}
	if f.failOps[op] {
		deny()
		return
	}
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	switch op {
	case "TrentService.ListKeys":
		io.WriteString(w, `{"Keys":[{"KeyId":"k1"},{"KeyId":"k2"},{"KeyId":"k3"}],"Truncated":false}`)
	case "TrentService.DescribeKey":
		switch in["KeyId"] {
		case "k1":
			io.WriteString(w, `{"KeyMetadata":{"KeyId":"k1","Arn":"arn:aws:kms:us-east-1:000000000000:key/k1","KeySpec":"RSA_2048"}}`)
		case "k2":
			deny()
		default:
			io.WriteString(w, `{"KeyMetadata":{"KeyId":"k3","KeySpec":"SYMMETRIC_DEFAULT"}}`)
		}
	case "TrentService.ListResourceTags":
		io.WriteString(w, `{"Tags":[{"TagKey":"owner","TagValue":"payments"}],"Truncated":false}`)
	case "CertificateManager.ListCertificates":
		io.WriteString(w, `{"CertificateSummaryList":[{"CertificateArn":"arn:aws:acm:us-east-1:000000000000:certificate/c1"}]}`)
	case "CertificateManager.DescribeCertificate":
		io.WriteString(w, `{"Certificate":{"CertificateArn":"arn:aws:acm:us-east-1:000000000000:certificate/c1","DomainName":"shop.example.test","KeyAlgorithm":"EC_prime256v1","NotAfter":1000000000}}`)
	case "CertificateManager.ListTagsForCertificate":
		io.WriteString(w, `{"Tags":[]}`)
	default:
		f.t.Errorf("unexpected operation %q", op)
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// isolateAWS points the SDK's default chain at the fake and at obviously fake
// static credentials, and away from any real config on the machine running
// the test.
func isolateAWS(t *testing.T, endpoint string) {
	dir := t.TempDir()
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
}

// The real SDK wiring, end to end against a fake endpoint: Scan builds both
// clients from the default config, inventories the readable keys and
// certificates, keeps going past a key it may not describe, and names that key
// as skipped rather than leaving it out silently.
func TestScanThroughTheRealSDKClients(t *testing.T) {
	fake := &fakeAWS{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	isolateAWS(t, srv.URL)

	findings, skipped, err := Scan(context.Background(), "us-east-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "kms key k2") || !strings.Contains(skipped[0], "AccessDenied") {
		t.Errorf("skipped = %v, want the undescribable key k2 named with its error", skipped)
	}

	got := map[string]bool{}
	for _, f := range findings {
		got[f.Source+" "+f.Asset.Algorithm+" "+string(f.Risk.Class)] = true
		if f.Source == "aws-kms" && f.Asset.Algorithm == "RSA" {
			if f.Asset.KeySize != 2048 || f.Tags["owner"] != "payments" || !strings.HasSuffix(f.Location.File, ":key/k1") {
				t.Errorf("RSA key finding: %+v", f)
			}
		}
	}
	for _, want := range []string{"aws-kms RSA ", "aws-kms AES ", "aws-acm ECDSA ", "aws-acm ECDSA expired"} {
		if !got[want] {
			t.Errorf("no %q finding in %v", want, got)
		}
	}
	if len(findings) != 4 {
		t.Errorf("got %d findings, want 4: %+v", len(findings), findings)
	}
}

// A listing the caller may not make is fatal for that service, and the error
// says which service; a profile that does not exist is a config error before
// any request is sent.
func TestScanErrorsNameTheService(t *testing.T) {
	for op, want := range map[string]string{
		"TrentService.ListKeys":               "kms:",
		"CertificateManager.ListCertificates": "acm:",
	} {
		fake := &fakeAWS{t: t, failOps: map[string]bool{op: true}}
		srv := httptest.NewServer(fake)
		isolateAWS(t, srv.URL)
		_, _, err := Scan(context.Background(), "us-east-1", "")
		srv.Close()
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s denied: got %v, want an error starting %q", op, err, want)
		}
	}

	fake := &fakeAWS{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	isolateAWS(t, srv.URL)
	if _, _, err := Scan(context.Background(), "us-east-1", "no-such-profile"); err == nil || !strings.Contains(err.Error(), "load aws config") {
		t.Errorf("an unknown profile: got %v", err)
	}
	if len(fake.seen) != 0 {
		t.Errorf("requests were sent despite the config error: %v", fake.seen)
	}
}
