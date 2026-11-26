package azure

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

const fakeTenant = "00000000-0000-0000-0000-000000000000"

// fakeAzure is one TLS server playing both the identity authority and the
// vault. The vault answers the SDK's first, unauthenticated request with the
// usual 401 challenge, then serves the key listing (two pages, to prove the
// pager is drained) and GetKey only to a bearer token the fake authority
// issued.
func fakeAzure(t *testing.T, refuseListing bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	n := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration"):
			io.WriteString(w, `{"token_endpoint":"`+base+`/`+fakeTenant+`/oauth2/v2.0/token","authorization_endpoint":"`+base+`/`+fakeTenant+`/oauth2/v2.0/authorize","issuer":"`+base+`/`+fakeTenant+`/v2.0"}`)
			return
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			io.WriteString(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"fake-token"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			w.Header().Set("WWW-Authenticate", `Bearer authorization="`+base+`/`+fakeTenant+`", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/keys" && refuseListing:
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":{"code":"Forbidden","message":"keys/list not granted"}}`)
		case r.URL.Path == "/keys" && r.URL.Query().Get("page") == "":
			io.WriteString(w, `{"value":[
				{"kid":"`+base+`/keys/rsa-key/v1","attributes":{"enabled":true},"tags":{"owner":"payments"}},
				{"kid":"`+base+`/keys/off-key/v1","attributes":{"enabled":false}},
				{"attributes":{"enabled":true}}
			],"nextLink":"`+base+`/keys?page=2&api-version=7.6"}`)
		case r.URL.Path == "/keys":
			io.WriteString(w, `{"value":[
				{"kid":"`+base+`/keys/ec-key/v2","attributes":{"enabled":true,"exp":1000000000}},
				{"kid":"`+base+`/keys/locked-key/v1","attributes":{"enabled":true}}
			]}`)
		case strings.HasPrefix(r.URL.Path, "/keys/rsa-key/"):
			io.WriteString(w, `{"key":{"kid":"`+base+`/keys/rsa-key/v1","kty":"RSA","n":"`+n+`","e":"AQAB"}}`)
		case strings.HasPrefix(r.URL.Path, "/keys/ec-key/"):
			io.WriteString(w, `{"key":{"kid":"`+base+`/keys/ec-key/v2","kty":"EC","crv":"P-256"}}`)
		case strings.HasPrefix(r.URL.Path, "/keys/locked-key/"):
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":{"code":"Forbidden","message":"keys/get not granted"}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sdkLister builds the production lister on the real azkeys client, with a
// client-secret credential against the fake authority. Both trust the fake's
// certificate through its own client; nothing else differs from Scan.
func sdkLister(t *testing.T, srv *httptest.Server) azureLister {
	t.Helper()
	credOpts := &azidentity.ClientSecretCredentialOptions{DisableInstanceDiscovery: true}
	credOpts.Transport = srv.Client()
	credOpts.Cloud.ActiveDirectoryAuthorityHost = srv.URL + "/"
	cred, err := azidentity.NewClientSecretCredential(fakeTenant, "qryx-test-client", "not-a-secret", credOpts)
	if err != nil {
		t.Fatal(err)
	}
	opts := &azkeys.ClientOptions{DisableChallengeResourceVerification: true}
	opts.Transport = srv.Client()
	client, err := azkeys.NewClient(srv.URL+"/", cred, opts)
	if err != nil {
		t.Fatal(err)
	}
	return azureLister{client}
}

// The real SDK wiring end to end: every page of the listing is drained,
// disabled keys and entries with no id are skipped, each key's type and
// modulus are read, an expired key gets its expiry finding, and a key that may
// be listed but not read is named rather than dropped.
func TestScanWithTheRealSDKClient(t *testing.T) {
	srv := fakeAzure(t, false)
	findings, skipped, err := scanWith(context.Background(), sdkLister(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "locked-key") {
		t.Errorf("skipped = %v, want locked-key named", skipped)
	}
	var rsa, ec, expired int
	for _, f := range findings {
		switch {
		case f.Asset.Algorithm == "RSA" && f.Asset.KeySize == 2048 && f.Tags["owner"] == "payments":
			rsa++
		case f.Asset.Algorithm == "ECDSA" && f.Risk.Class == "expired":
			expired++
		case f.Asset.Algorithm == "ECDSA":
			ec++
		default:
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if rsa != 1 || ec != 1 || expired != 1 {
		t.Errorf("rsa=%d ec=%d expired=%d, want one each: %+v", rsa, ec, expired, findings)
	}
}

// A vault that refuses the listing ends the inventory with an error.
func TestScanWithTheRealSDKClientFailsOnARefusedListing(t *testing.T) {
	srv := fakeAzure(t, true)
	findings, _, err := scanWith(context.Background(), sdkLister(t, srv))
	if err == nil || !strings.Contains(err.Error(), "keys/list not granted") {
		t.Fatalf("got %d findings and %v, want the vault's refusal", len(findings), err)
	}
}
