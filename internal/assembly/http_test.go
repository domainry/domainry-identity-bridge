package assembly

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/modulehttp"
	"github.com/domainry/domainry-identity-bridge/config"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

func TestHTTPAdapterAndCookieOriginBoundary(t *testing.T) {
	h := openHost(t, filepath.Join(t.TempDir(), "bridge.db"))
	b := testBinding(t, h, "app")
	publish(t, b)
	b.Config.Browser = &config.Browser{DisplayName: "Accounts", LoginURL: "https://accounts.example.com/login", LogoutURL: "https://accounts.example.com/logout", Credential: config.Credential{Location: "cookie", Name: "account_session"}, AllowedOrigins: []string{"https://app.example.com"}}
	adapter := b.HTTPAdapters()[0]
	if err := modulehttp.ValidateAdapter(adapter); err != nil {
		t.Fatal(err)
	}
	middleware, err := httpmiddleware.New(b.Service, httpmiddleware.WithBindingCredential(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, origin string
		want           int
	}{{"GET", "", 200}, {"POST", "", 403}, {"POST", "https://evil.example.com", 403}, {"POST", "https://app.example.com", 204}, {"GET", "https://evil.example.com", 403}} {
		request := httptest.NewRequest(tc.method, sessionPath, nil)
		request.AddCookie(&http.Cookie{Name: "account_session", Value: "external-credential-never-returned"})
		if tc.origin != "" {
			request.Header.Set("Origin", tc.origin)
		}
		response := httptest.NewRecorder()
		next := adapter.Handler()
		if tc.method == "POST" {
			next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		}
		middleware.Authenticate(next).ServeHTTP(response, request)
		if response.Code != tc.want {
			t.Fatalf("%s %s: %d %s", tc.method, tc.origin, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "external-credential-never-returned") {
			t.Fatal("credential exposed")
		}
	}
	response := httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, httptest.NewRequest("GET", discoveryPath, nil))
	for _, secret := range []string{"service_headers", "verification", "account_session"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("discovery exposes verifier configuration")
		}
	}
}
