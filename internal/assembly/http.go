package assembly

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/modulehttp"
	bridge "github.com/domainry/domainry-identity-bridge"
	bridgecapability "github.com/domainry/domainry-identity-bridge/capability"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

const discoveryPath = bridgecapability.ExternalConfigPath
const sessionPath = bridgecapability.ExternalSessionPath

func (b *Binding) ReadAccessCredential(r *http.Request) (string, error) {
	if b.Config.Browser == nil {
		token, ok := httpmiddleware.BearerToken(r)
		if !ok {
			return "", nil
		}
		return token, nil
	}
	cfg := b.Config.Browser
	origin := r.Header.Get("Origin")
	unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
	if origin != "" && !includes(cfg.AllowedOrigins, origin) || cfg.Credential.Location == "cookie" && unsafe && origin == "" {
		return "", &identity.Error{StatusCode: 403, Code: "identity.external_origin_denied"}
	}
	if cfg.Credential.Location == "cookie" {
		var value string
		count := 0
		for _, cookie := range r.Cookies() {
			if cookie.Name == cfg.Credential.Name {
				value = cookie.Value
				count++
			}
		}
		if count > 1 {
			return "", &identity.Error{StatusCode: 401, Code: "auth.token_invalid"}
		}
		return value, nil
	}
	values := r.Header.Values(cfg.Credential.Name)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !strings.HasPrefix(values[0], cfg.Credential.Prefix) {
		return "", &identity.Error{StatusCode: 401, Code: "auth.token_invalid"}
	}
	return strings.TrimPrefix(values[0], cfg.Credential.Prefix), nil
}

func (b *Binding) HTTPAdapters() []modulehttp.Adapter { return []modulehttp.Adapter{browserAdapter{b}} }

type browserAdapter struct{ binding *Binding }

func (browserAdapter) ContractVersion() string { return modulehttp.ContractVersion }
func (browserAdapter) Owner() string           { return "identity" }
func (browserAdapter) Name() string            { return "external_identity" }
func (browserAdapter) Routes() []modulehttp.Route {
	return bridgecapability.ExternalAdapterRoutes()
}
func (a browserAdapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+bridgecapability.ExternalClientPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(bridge.BrowserClientSource))
	})
	mux.HandleFunc("GET "+discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		browser := a.binding.Config.Browser
		public := bridgecapability.BrowserConfigResponse{Mode: "external", SessionPath: sessionPath, ApplicationKey: a.binding.Config.ApplicationKey}
		if browser != nil {
			public.DisplayName = browser.DisplayName
			public.LoginURL = browser.LoginURL
			public.LogoutURL = &browser.LogoutURL
			public.Credential = &bridgecapability.BrowserCredentialResponse{Location: browser.Credential.Location}
			if browser.Credential.Location == "header" {
				public.Credential.Name = browser.Credential.Name
				public.Credential.Prefix = browser.Credential.Prefix
			}
		}
		json.NewEncoder(w).Encode(public)
	})
	mux.HandleFunc("GET "+sessionPath, func(w http.ResponseWriter, r *http.Request) {
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || !principal.Known {
			http.Error(w, "authentication required", 401)
			return
		}
		roles, err := a.binding.assignedRoles(r.Context(), principal.WorkspaceID, principal.UserID)
		if err != nil {
			http.Error(w, "external session unavailable", 503)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bridgecapability.BrowserSessionResponse{WorkspaceID: principal.WorkspaceID, SubjectID: principal.UserID, User: principal.User, Roles: roles, Permissions: principal.PermissionKeys(), AuthorizationRevision: principal.AuthorizationRevision, ExpiresAt: principal.AccessBundle.ExpiresAt, AccessBundle: principal.AccessBundle})
	})
	return mux
}
