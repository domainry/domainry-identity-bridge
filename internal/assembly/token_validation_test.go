package assembly

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domainry/domainry-identity-bridge/config"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

// The fixture follows the existing account service's token validation contract:
// HTTP 200 may contain an authentication error; only the business response is
// authoritative. The service receives JSON, while the browser sends a Cookie.
func TestTokenValidationCookieSessionUsesExistingContract(t *testing.T) {
	file, err := os.Open("../../examples/token-validation.config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Credential.Name = "deployment_cookie"
	fixedNow := time.Now().UTC().Truncate(time.Second)
	expiresAt := fixedNow.Add(time.Minute).Unix()
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]string
		if r.Method != "POST" || r.URL.Path != "/passport/token/validate" || r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" ||
			json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["token"] == "" {
			t.Error("browser credential did not follow the configured JSON validation protocol")
			http.Error(w, "invalid request", 400)
			return
		}
		data := map[string]any{"valid": true, "user_id": int64(9007199254740993), "email": "person@example.com", "token_type": "access", "expires_at": expiresAt}
		response := map[string]any{"errCode": 0, "errMsg": "success", "data": data}
		switch body["token"] {
		case "valid-credential":
		case "account-unavailable":
			data["valid"] = false
		case "refresh-credential":
			data["token_type"] = "refresh"
		case "expired-credential":
			data["expires_at"] = fixedNow.Unix()
		case "missing-expiry":
			delete(data, "expires_at")
		case "missing-type":
			delete(data, "token_type")
		case "wrong-valid-type":
			data["valid"] = "true"
		case "business-error-with-data":
			response["errCode"] = 100003
		default:
			response = map[string]any{"errCode": 100003, "errMsg": "invalid token", "data": nil}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	cfg.Provider.Verification.Endpoint = server.URL + "/passport/token/validate"
	host := openHost(t, filepath.Join(t.TempDir(), "bridge.db"))
	binding, err := Open(t.Context(), cfg, identity.ApplicationRef{WorkspaceID: "installation", ApplicationKey: identity.ApplicationKey(cfg.ApplicationKey)},
		identity.DatabaseHandle{Pool: host.db, Driver: "sqlite", ModuleMigrations: host, ExternalWorkspaces: host}, server.Client().Transport, nil, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	publish(t, binding)
	middleware, err := httpmiddleware.New(binding.PrincipalAuthenticator(), httpmiddleware.WithBindingCredential(binding))
	if err != nil {
		t.Fatal(err)
	}
	route := middleware.Authenticate(binding.HTTPAdapters()[0].Handler())
	request := func(credential string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", sessionPath, nil)
		r.AddCookie(&http.Cookie{Name: cfg.Browser.Credential.Name, Value: credential})
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		return w
	}
	var firstWorkspace string
	for range 2 {
		response := request("valid-credential")
		if response.Code != 200 || strings.Contains(response.Body.String(), "valid-credential") {
			t.Fatalf("session status=%d or credential exposed", response.Code)
		}
		var session struct {
			WorkspaceID string    `json:"workspace_id"`
			SubjectID   string    `json:"subject_id"`
			ExpiresAt   time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
			t.Fatal(err)
		}
		if session.WorkspaceID == "" || session.SubjectID == "" || session.ExpiresAt.Unix() != expiresAt || firstWorkspace != "" && session.WorkspaceID != firstWorkspace {
			t.Fatalf("invalid or unstable session: %+v", session)
		}
		firstWorkspace = session.WorkspaceID
		owner, err := binding.ownerForUser(t.Context(), session.WorkspaceID, session.SubjectID)
		if err != nil || owner.Binding.ExternalSubjectID != "9007199254740993" {
			t.Fatalf("provider user ID lost precision: %q, %v", owner.Binding.ExternalSubjectID, err)
		}
	}
	for _, credential := range []string{"invalid-credential", "account-unavailable", "refresh-credential", "expired-credential", "missing-expiry", "missing-type", "wrong-valid-type", "business-error-with-data"} {
		t.Run(credential, func(t *testing.T) {
			if response := request(credential); response.Code != 401 {
				t.Fatalf("rejected provider response created a session: status=%d", response.Code)
			}
		})
	}
	var count int
	if err := host.db.QueryRow("SELECT COUNT(*) FROM host_workspaces").Scan(&count); err != nil || count != 1 {
		t.Fatalf("rejected or repeated login allocated another Workspace: count=%d, %v", count, err)
	}
	if calls.Load() != 10 {
		t.Fatalf("each request must reach the account authority: calls=%d", calls.Load())
	}
}
