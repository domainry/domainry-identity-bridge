package moduleassembly

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

	"github.com/domainry/domainry-identity-bridge/internal/config"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

// The fixture follows the existing account service's token validation contract:
// HTTP 200 may contain an authentication error; only the business response is
// authoritative. The service receives JSON, while the browser sends a Cookie.
func TestTokenValidationCookieSessionUsesExistingContract(t *testing.T) {
	file, err := os.Open("../../../docs/examples/token-validation.config.json")
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
	var validationCalls atomic.Int64
	var profileCalls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/inner/user/info" {
			profileCalls.Add(1)
			cookie, cookieErr := r.Cookie("token")
			if r.Method != http.MethodGet || cookieErr != nil || cookie.Value != "valid-credential" || r.Header.Get("Authorization") != "" {
				t.Error("profile request did not follow the configured Cookie protocol")
				http.Error(w, "invalid request", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"errCode": 0, "data": map[string]any{"user_id": int64(9007199254740993), "user_name": "Person", "email": "person@example.com"}})
			return
		}
		validationCalls.Add(1)
		var body map[string]string
		if r.Method != "POST" || r.URL.Path != "/passport/token/validate" || r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" ||
			json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["token"] == "" {
			t.Error("browser credential did not follow the configured JSON validation protocol")
			http.Error(w, "invalid request", 400)
			return
		}
		data := map[string]any{"valid": true, "user_id": int64(9007199254740993), "token_type": "access", "expires_at": expiresAt}
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
	cfg.Provider.Profile.Endpoint = server.URL + "/passport/inner/user/info"
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
			User        struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"user"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
			t.Fatal(err)
		}
		if session.WorkspaceID == "" || session.SubjectID == "" || session.User.Name != "Person" || session.User.Email != "person@example.com" || session.ExpiresAt.Unix() != expiresAt || firstWorkspace != "" && session.WorkspaceID != firstWorkspace {
			t.Fatalf("invalid or unstable session: %+v", session)
		}
		firstWorkspace = session.WorkspaceID
		owner, err := binding.memberForUser(t.Context(), session.WorkspaceID, session.SubjectID)
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
	if validationCalls.Load() != 10 || profileCalls.Load() != 2 {
		t.Fatalf("unexpected authority calls: validation=%d profile=%d", validationCalls.Load(), profileCalls.Load())
	}
}
