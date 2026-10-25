package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/config"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
)

func profileProvider(endpoint string) config.Provider {
	return config.Provider{
		Key: "accounts",
		Verification: config.Verification{
			Kind: "http_introspection", Endpoint: endpoint + "/validate", Method: "POST", Timeout: "1s", MaxResponseBytes: 65536,
			Credential: config.Credential{Location: "json", Name: "token"},
			Response: config.Response{
				SubjectID: "/data/user_id", ExpiresAt: "/data/expires_at", ExpiryFormat: "unix_seconds",
				Checks: []config.ResponseCheck{{Path: "/errCode", Equals: json.RawMessage(`0`)}, {Path: "/data/valid", Equals: json.RawMessage(`true`)}},
			},
		},
		Profile: &config.Profile{
			Kind: "http_profile", Endpoint: endpoint + "/profile", Method: "GET", Timeout: "1s", MaxResponseBytes: 65536,
			Credential: config.Credential{Location: "cookie", Name: "token"},
			Response: config.ProfileResponse{
				SubjectID: "/data/user_id", DisplayName: "/data/user_name", Email: "/data/email",
				Checks: []config.ResponseCheck{{Path: "/errCode", Equals: json.RawMessage(`0`)}},
			},
		},
	}
}

func TestHTTPVerifyEnrichesProfileBoundToVerifiedSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/validate":
			var body map[string]string
			if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&body) != nil || body["token"] != "credential" {
				t.Fatalf("invalid validation request")
			}
			_, _ = w.Write([]byte(`{"errCode":0,"data":{"valid":true,"user_id":9007199254740993,"expires_at":1900000000}}`))
		case "/profile":
			cookie, err := request.Cookie("token")
			if request.Method != http.MethodGet || err != nil || cookie.Value != "credential" {
				t.Fatalf("invalid profile request")
			}
			_, _ = w.Write([]byte(`{"errCode":0,"data":{"user_id":9007199254740993,"user_name":"Ada","email":"ada@example.com"}}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	provider, err := New(profileProvider(server.URL), server.Client().Transport, nil, func() time.Time { return time.Unix(1800000000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	subject, err := provider.Verify(t.Context(), "credential")
	if err != nil {
		t.Fatal(err)
	}
	if subject.SubjectID != "9007199254740993" || subject.DisplayName != "Ada" || subject.Email != "ada@example.com" {
		t.Fatalf("subject = %+v", subject)
	}
}

func TestHTTPVerifyRejectsProfileForAnotherSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/validate" {
			_, _ = w.Write([]byte(`{"errCode":0,"data":{"valid":true,"user_id":42,"expires_at":1900000000}}`))
			return
		}
		_, _ = w.Write([]byte(`{"errCode":0,"data":{"user_id":43,"user_name":"Other","email":"other@example.com"}}`))
	}))
	defer server.Close()

	provider, err := New(profileProvider(server.URL), server.Client().Transport, nil, func() time.Time { return time.Unix(1800000000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Verify(t.Context(), "credential"); !errors.Is(err, bridge.ErrProviderResponse) {
		t.Fatalf("error = %v, want provider response error", err)
	}
}
