package module_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domainry/domainry-identity-bridge/module"
	"github.com/domainry/domainry-identity-bridge/module/config"
	"github.com/domainry/domainry-identity-sdk/authorization"
)

var now = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func configuration(t *testing.T) config.Config {
	t.Helper()
	file, err := os.Open("../docs/examples/personal.config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// hostFixture is a test double, not a production durability implementation.
type hostFixture struct {
	mu             sync.Mutex
	requests       []module.PersonalWorkspaceRequest
	bindings       map[string]module.WorkspaceBinding
	policyCalls    int
	alterWorkspace func(*module.WorkspaceBinding)
	alterPolicy    func(*authorization.AccessBundle)
}

func (host *hostFixture) ResolvePersonalWorkspace(_ context.Context, req module.PersonalWorkspaceRequest) (module.WorkspaceBinding, error) {
	host.mu.Lock()
	defer host.mu.Unlock()
	host.requests = append(host.requests, req)
	if host.bindings == nil {
		host.bindings = make(map[string]module.WorkspaceBinding)
	}
	value, found := host.bindings[req.IdempotencyKey]
	if !found {
		if !req.CreateIfMissing {
			return module.WorkspaceBinding{}, errors.New("missing")
		}
		value = module.WorkspaceBinding{InstallationID: req.InstallationID, ProviderKey: req.ProviderKey, ExternalSubjectID: req.ExternalSubjectID,
			WorkspaceID: fmt.Sprintf("workspace-%d", len(host.bindings)+1), UserID: fmt.Sprintf("user-%d", len(host.bindings)+1), Active: true}
		host.bindings[req.IdempotencyKey] = value
	}
	if host.alterWorkspace != nil {
		host.alterWorkspace(&value)
	}
	return value, nil
}

func (host *hostFixture) ResolveAccess(_ context.Context, request module.PolicyRequest) (authorization.AccessBundle, error) {
	host.mu.Lock()
	defer host.mu.Unlock()
	host.policyCalls++
	bundle := authorization.AccessBundle{
		ContractVersion: authorization.CurrentPolicyBundleVersion, AuthorizationRevision: "revision-1", ExpiresAt: now.Add(time.Hour),
		Subject:        authorization.Subject{WorkspaceID: authorization.WorkspaceID(request.Workspace.WorkspaceID), SubjectID: authorization.SubjectID(request.Workspace.UserID)},
		FunctionGrants: []authorization.FunctionGrant{{Resource: "notes", Action: "read", Effect: authorization.EffectAllow}},
		DataPolicies:   []authorization.DataPolicy{{Key: "notes-read", Resource: "notes", Action: "read", Effect: authorization.EffectAllow, DataScopes: []authorization.DataScope{authorization.DataScopeAll}}},
	}
	if host.alterPolicy != nil {
		host.alterPolicy(&bundle)
	}
	return bundle, nil
}

func open(t *testing.T, cfg config.Config, host *hostFixture, server *httptest.Server) *module.Module {
	t.Helper()
	cfg.Provider.Verification.Endpoint = server.URL
	value, err := module.Open(cfg, module.Host{Workspaces: host, Policies: host}, module.Options{
		Transport: server.Client().Transport, Now: func() time.Time { return now },
		LookupEnvironment: func(string) (string, bool) { return "service-secret", true },
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func response(subject any) map[string]any {
	return map[string]any{"data": map[string]any{"active": true, "token_type": "access", "audience": "example-application",
		"expires_at": now.Add(10 * time.Minute).Unix(), "subject": map[string]any{"id": subject, "name": "Alex", "email": "alex@example.com"}}}
}

func TestConfiguredVerificationProducesSDKPrincipal(t *testing.T) {
	cfg := configuration(t)
	cfg.Provider.Key = "custom-provider"
	cfg.Provider.Verification.Response.SubjectID = "/account/items/0/id~1external"
	cfg.Provider.Verification.Response.DisplayName = "/account/name"
	cfg.Provider.Verification.Response.Email = ""
	cfg.Provider.Verification.Response.ExpiresAt = "/valid_until"
	cfg.Provider.Verification.Response.ExpiryFormat = "rfc3339"
	cfg.Provider.Verification.Response.Checks = []config.ResponseCheck{{Path: "/state", Equals: json.RawMessage(`"valid"`)}}
	cfg.Provider.Verification.Credential = config.Credential{Location: "json", Name: "session_credential"}
	cfg.PersonalWorkspace.NameTemplate = "{{.DisplayName}}'s workspace"
	cfg.PersonalWorkspace.InitialRoleKeys = []string{"project_member"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if r.Method != "POST" || body["session_credential"] != "opaque-access-token" || r.Header.Get("X-Application-Credential") != "service-secret" {
			t.Error("configured credential transport was not respected")
		}
		fmt.Fprintf(w, `{"state":"valid","valid_until":%q,"account":{"name":"Alex","items":[{"id/external":9007199254740993}]}}`, now.Add(time.Minute).Format(time.RFC3339))
	}))
	defer server.Close()
	host := &hostFixture{}
	value := open(t, cfg, host, server)
	// Caller mutation must not change the composed module's role configuration.
	cfg.PersonalWorkspace.InitialRoleKeys[0] = "unexpected_role"
	principal, err := value.Authenticate(context.Background(), "opaque-access-token")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || !principal.HasPermission("notes.read") || principal.HasPermission("notes.delete") {
		t.Fatalf("unexpected policy: %+v", principal)
	}
	if principal.UserID != "user-1" || principal.WorkspaceID != "workspace-1" || principal.User.Name != "Alex" {
		t.Fatalf("unexpected identity: %+v", principal)
	}
	if !principal.AccessBundle.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("policy outlives external credential")
	}
	request := host.requests[0]
	if request.ExternalSubjectID != "9007199254740993" || request.ProviderKey != "custom-provider" || request.Name != "Alex's workspace" || request.InitialRoleKeys[0] != "project_member" {
		t.Fatalf("unexpected provisioning request: %+v", request)
	}
}

func TestRejectsUnverifiedCredentialsBeforeProvisioning(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		mutate   func(map[string]any)
		raw      string
		maxBytes int64
		expected error
	}{
		{name: "inactive", mutate: func(d map[string]any) { d["active"] = false }, expected: module.ErrCredentialRejected},
		{name: "missing active", mutate: func(d map[string]any) { delete(d, "active") }, expected: module.ErrCredentialRejected},
		{name: "string true", mutate: func(d map[string]any) { d["active"] = "true" }, expected: module.ErrCredentialRejected},
		{name: "refresh credential", mutate: func(d map[string]any) { d["token_type"] = "refresh" }, expected: module.ErrCredentialRejected},
		{name: "wrong application", mutate: func(d map[string]any) { d["audience"] = "different-app" }, expected: module.ErrCredentialRejected},
		{name: "expired", mutate: func(d map[string]any) { d["expires_at"] = now.Unix() }, expected: module.ErrCredentialRejected},
		{name: "missing subject", mutate: func(d map[string]any) { delete(d, "subject") }, expected: module.ErrProviderResponse},
		{name: "fractional ID", mutate: func(d map[string]any) { d["subject"].(map[string]any)["id"] = 1.5 }, expected: module.ErrProviderResponse},
		{name: "unauthorized", status: 401, expected: module.ErrCredentialRejected},
		{name: "provider failure", status: 500, raw: "opaque-access-token service-secret", expected: module.ErrProviderUnavailable},
		{name: "oversized response", maxBytes: 10, expected: module.ErrProviderResponse},
		{name: "malformed JSON", raw: `{"data":`, expected: module.ErrProviderResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer opaque-access-token" {
					t.Error("missing user credential")
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				if test.raw != "" {
					io.WriteString(w, test.raw)
					return
				}
				body := response("source-user")
				if test.mutate != nil {
					test.mutate(body["data"].(map[string]any))
				}
				json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			cfg := configuration(t)
			if test.maxBytes != 0 {
				cfg.Provider.Verification.MaxResponseBytes = test.maxBytes
			}
			host := &hostFixture{}
			value := open(t, cfg, host, server)
			_, err := value.Authenticate(context.Background(), "opaque-access-token")
			if !errors.Is(err, test.expected) {
				t.Fatalf("got %v, want %v", err, test.expected)
			}
			if strings.Contains(err.Error(), "opaque-access-token") || strings.Contains(err.Error(), "service-secret") {
				t.Fatal("credential leaked through error")
			}
			if len(host.requests) != 0 {
				t.Fatal("unverified caller reached workspace authority")
			}
		})
	}
}

func TestRedirectDoesNotForwardCredential(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/another-path", http.StatusFound)
	}))
	defer server.Close()
	host := &hostFixture{}
	_, err := open(t, configuration(t), host, server).Authenticate(context.Background(), "access-token")
	if !errors.Is(err, module.ErrProviderUnavailable) || calls != 1 || len(host.requests) != 0 {
		t.Fatalf("redirect handling: calls=%d err=%v", calls, err)
	}
}

func TestWorkspaceAndPolicyMustMatchVerifiedOwner(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(response("subject-a")) }))
	defer server.Close()
	for _, test := range []struct {
		name      string
		workspace func(*module.WorkspaceBinding)
		policy    func(*authorization.AccessBundle)
		expected  error
	}{
		{name: "wrong owner", workspace: func(w *module.WorkspaceBinding) { w.ExternalSubjectID = "subject-b" }, expected: module.ErrWorkspaceMismatch},
		{name: "wrong provider", workspace: func(w *module.WorkspaceBinding) { w.ProviderKey = "another-provider" }, expected: module.ErrWorkspaceMismatch},
		{name: "wrong installation", workspace: func(w *module.WorkspaceBinding) { w.InstallationID = "other" }, expected: module.ErrWorkspaceMismatch},
		{name: "reserved workspace", workspace: func(w *module.WorkspaceBinding) { w.WorkspaceID = "default" }, expected: module.ErrWorkspaceMismatch},
		{name: "suspended workspace", workspace: func(w *module.WorkspaceBinding) { w.Active = false }, expected: module.ErrWorkspaceInactive},
		{name: "wrong policy workspace", policy: func(p *authorization.AccessBundle) { p.Subject.WorkspaceID = "other" }, expected: module.ErrPolicyMismatch},
		{name: "wrong policy user", policy: func(p *authorization.AccessBundle) { p.Subject.SubjectID = "other" }, expected: module.ErrPolicyMismatch},
		{name: "expired policy", policy: func(p *authorization.AccessBundle) { p.ExpiresAt = now }, expected: module.ErrPolicyUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := &hostFixture{alterWorkspace: test.workspace, alterPolicy: test.policy}
			_, err := open(t, configuration(t), host, server).Authenticate(context.Background(), "access-token")
			if !errors.Is(err, test.expected) {
				t.Fatalf("got %v want %v", err, test.expected)
			}
			if test.workspace != nil && host.policyCalls != 0 {
				t.Fatal("invalid workspace reached policy authority")
			}
		})
	}
}

func TestConcurrentRequestsUseStablePersonalOwnershipKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(response(cookie.Value))
	}))
	defer server.Close()
	cfg := configuration(t)
	cfg.Provider.Verification.Method = "GET"
	cfg.Provider.Verification.Credential = config.Credential{Location: "cookie", Name: "session_id"}
	host := &hostFixture{}
	value := open(t, cfg, host, server)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			principal, err := value.Authenticate(context.Background(), "subject-a")
			if err != nil || principal.WorkspaceID != "workspace-1" {
				t.Errorf("principal=%+v err=%v", principal, err)
			}
		})
	}
	wg.Wait()
	firstKey := host.requests[0].IdempotencyKey
	for _, request := range host.requests {
		if request.IdempotencyKey != firstKey {
			t.Fatal("same owner produced different provisioning keys")
		}
	}
	// Application authorization changes do not change ownership identity.
	cfg.ApplicationKey = "second-application"
	if _, err := open(t, cfg, host, server).Authenticate(context.Background(), "subject-a"); err != nil {
		t.Fatal(err)
	}
	if host.requests[len(host.requests)-1].IdempotencyKey != firstKey {
		t.Fatal("application allocated another personal workspace")
	}
	if _, err := value.Authenticate(context.Background(), "subject-b"); err != nil {
		t.Fatal(err)
	}
	if host.requests[len(host.requests)-1].IdempotencyKey == firstKey {
		t.Fatal("different users share an ownership key")
	}
	cfg.Provider.Key = "second-provider"
	if _, err := open(t, cfg, host, server).Authenticate(context.Background(), "subject-a"); err != nil {
		t.Fatal(err)
	}
	if host.requests[len(host.requests)-1].IdempotencyKey == firstKey {
		t.Fatal("different providers share an ownership key")
	}
}

func TestLookupOnlyAndMissingDependencies(t *testing.T) {
	cfg := configuration(t)
	host := &hostFixture{}
	if _, err := module.Open(cfg, module.Host{}, module.Options{}); err == nil {
		t.Fatal("missing authorities accepted")
	}
	if _, err := module.Open(cfg, module.Host{Workspaces: host, Policies: host}, module.Options{LookupEnvironment: func(string) (string, bool) { return "", false }}); err == nil {
		t.Fatal("missing service credential accepted")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(response("subject")) }))
	defer server.Close()
	cfg.PersonalWorkspace.CreateOnFirstAccess = false
	if _, err := open(t, cfg, host, server).Authenticate(context.Background(), "access-token"); !errors.Is(err, module.ErrWorkspaceUnavailable) {
		t.Fatalf("unexpected error %v", err)
	}
	if len(host.bindings) != 0 || host.requests[0].CreateIfMissing {
		t.Fatal("lookup-only mode requested creation")
	}
}
