package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
)

// fakeKMS answers the three Cloud KMS REST listings the lister drains:
// key rings, the keys in a ring, and the versions of a key. Ring r1 holds one
// readable key with an enabled and a disabled version and one key whose
// versions may not be listed; ring r2 may not have its keys listed at all.
func fakeKMS(t *testing.T, failRings bool) *httptest.Server {
	t.Helper()
	const loc = "/v1/projects/p1/locations/-"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		deny := func() {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":{"code":403,"message":"permission denied","status":"PERMISSION_DENIED"}}`))
		}
		switch r.URL.Path {
		case loc + "/keyRings":
			if failRings {
				deny()
				return
			}
			w.Write([]byte(`{"keyRings":[{"name":"projects/p1/locations/eu/keyRings/r1"},{"name":"projects/p1/locations/us/keyRings/r2"}]}`))
		case "/v1/projects/p1/locations/eu/keyRings/r1/cryptoKeys":
			w.Write([]byte(`{"cryptoKeys":[
				{"name":"projects/p1/locations/eu/keyRings/r1/cryptoKeys/sign","labels":{"owner":"payments"}},
				{"name":"projects/p1/locations/eu/keyRings/r1/cryptoKeys/hidden"}]}`))
		case "/v1/projects/p1/locations/us/keyRings/r2/cryptoKeys":
			deny()
		case "/v1/projects/p1/locations/eu/keyRings/r1/cryptoKeys/sign/cryptoKeyVersions":
			w.Write([]byte(`{"cryptoKeyVersions":[
				{"name":"projects/p1/locations/eu/keyRings/r1/cryptoKeys/sign/cryptoKeyVersions/1","state":"ENABLED","algorithm":"RSA_SIGN_PSS_2048_SHA256"},
				{"name":"projects/p1/locations/eu/keyRings/r1/cryptoKeys/sign/cryptoKeyVersions/2","state":"DISABLED","algorithm":"EC_SIGN_P256_SHA256"}]}`))
		case "/v1/projects/p1/locations/eu/keyRings/r1/cryptoKeys/hidden/cryptoKeyVersions":
			deny()
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func restLister(t *testing.T, srv *httptest.Server) gcpLister {
	t.Helper()
	c, err := kms.NewKeyManagementRESTClient(context.Background(),
		option.WithEndpoint(srv.URL), option.WithoutAuthentication(), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return gcpLister{client: c}
}

// The real iterator wiring, through the SDK's own client against a fake
// endpoint: enabled versions are inventoried with their key's labels, disabled
// ones are not, and a ring or key whose contents may not be listed is skipped
// and named rather than ending the inventory.
func TestListDrainsTheRealIteratorsAndNamesWhatItSkipped(t *testing.T) {
	l := restLister(t, fakeKMS(t, false))
	findings, skipped, err := scanWith(context.Background(), l, "p1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %+v, want the one enabled version", findings)
	}
	f := findings[0]
	if f.Asset.Algorithm != "RSA" || f.Asset.KeySize != 2048 || f.Tags["owner"] != "payments" || !strings.HasSuffix(f.Location.File, "/cryptoKeyVersions/1") {
		t.Errorf("finding %+v", f)
	}
	joined := strings.Join(skipped, "\n")
	if len(skipped) != 2 || !strings.Contains(joined, "kms key ring projects/p1/locations/us/keyRings/r2") || !strings.Contains(joined, "kms key projects/p1/locations/eu/keyRings/r1/cryptoKeys/hidden") {
		t.Errorf("skipped = %v, want ring r2 and key hidden named", skipped)
	}
}

// Without the ring listing there is nothing to walk, so that one is fatal.
func TestListFailsWhenTheRingsCannotBeListed(t *testing.T) {
	l := restLister(t, fakeKMS(t, true))
	if findings, _, err := scanWith(context.Background(), l, "p1", ""); err == nil {
		t.Fatalf("a refused ring listing returned %d findings and no error", len(findings))
	}
}
