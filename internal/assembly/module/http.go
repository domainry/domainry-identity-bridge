package moduleassembly

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/httpresponse"
	"github.com/domainry/domainry-foundation/modulehttp"
	"github.com/domainry/domainry-identity-bridge/internal/application"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	browser "github.com/domainry/domainry-identity-bridge/internal/transport/browser"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

const discoveryPath = externalConfigPath
const sessionPath = externalSessionPath

func (b *Binding) ReadAccessCredential(r *http.Request) (string, error) {
	if r == nil {
		return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "auth.token_invalid"}
	}
	credential, err := b.readAccessCredential(r)
	if err != nil {
		return "", err
	}
	if b.Config.Workspace.Mode != "per_external_group" {
		return credential, nil
	}
	selector := b.Config.Workspace.Selector
	values := r.Header.Values(selector.Name)
	if len(values) != 1 {
		return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "identity.external_workspace_denied"}
	}
	selected := strings.TrimSpace(values[0])
	if selected == "" || selected != values[0] || len(selected) > 512 || strings.ContainsAny(selected, "\x00\r\n") {
		return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "identity.external_workspace_denied"}
	}
	// RequestCredentialBinding predates external Workspace selection. Updating
	// this request's context preserves the raw provider token while carrying the
	// untrusted selector to this Binding's membership verifier.
	*r = *r.WithContext(application.WithSelectedWorkspace(r.Context(), selected))
	return credential, nil
}

func (b *Binding) readAccessCredential(r *http.Request) (string, error) {
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
		return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "identity.external_origin_denied"}
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
			return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "auth.token_invalid"}
		}
		return value, nil
	}
	values := r.Header.Values(cfg.Credential.Name)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !strings.HasPrefix(values[0], cfg.Credential.Prefix) {
		return "", &identity.Error{Class: identity.ErrorClassForbidden, Code: "auth.token_invalid"}
	}
	return strings.TrimPrefix(values[0], cfg.Credential.Prefix), nil
}

func (b *Binding) HTTPAdapters() []modulehttp.Adapter { return []modulehttp.Adapter{browserAdapter{b}} }

type browserAdapter struct{ binding *Binding }

func (browserAdapter) ContractVersion() string { return modulehttp.ContractVersion }
func (browserAdapter) Owner() string           { return "identity" }
func (browserAdapter) Name() string            { return "external_identity" }
func (browserAdapter) Routes() []modulehttp.Route {
	return externalAdapterRoutes()
}
func (a browserAdapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+externalClientPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(browser.Source))
	})
	mux.HandleFunc("GET "+discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		browser := a.binding.Config.Browser
		public := browserConfigResponse{Mode: "external", SessionPath: sessionPath, ApplicationKey: a.binding.Config.ApplicationKey, WorkspaceMode: a.binding.Config.Workspace.Mode}
		if a.binding.Config.Workspace.Mode == "per_external_group" {
			public.WorkspacesPath = externalWorkspacesPath
		}
		if browser != nil {
			public.DisplayName = browser.DisplayName
			public.LoginURL = browser.LoginURL
			public.LogoutURL = &browser.LogoutURL
			public.Credential = &browserCredentialResponse{Location: browser.Credential.Location}
			if browser.Credential.Location == "header" {
				public.Credential.Name = browser.Credential.Name
				public.Credential.Prefix = browser.Credential.Prefix
			}
		}
		if selector := a.binding.Config.Workspace.Selector; selector != nil {
			public.WorkspaceSelector = &browserWorkspaceSelectorResponse{Location: selector.Location, Name: selector.Name}
		}
		json.NewEncoder(w).Encode(public)
	})
	mux.HandleFunc("GET "+externalWorkspacesPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		credential, err := a.binding.readAccessCredential(r)
		if err != nil || credential == "" {
			httpresponse.WriteError(w, r, httpresponse.Failure{Status: http.StatusUnauthorized, Code: "identity.external.login_required", Message: "External login is required.", Cause: err})
			return
		}
		workspaces, err := a.binding.Service.ExternalWorkspaces(r.Context(), credential)
		if err != nil {
			status := http.StatusServiceUnavailable
			code := "identity.external.workspaces_unavailable"
			message := "External Workspaces are unavailable."
			if errors.Is(err, bridge.ErrCredentialRejected) {
				status = http.StatusUnauthorized
				code = "identity.external.login_required"
				message = "External login is required."
			} else if errors.Is(err, bridge.ErrProviderResponse) {
				status = http.StatusBadGateway
			}
			httpresponse.WriteError(w, r, httpresponse.Failure{Status: status, Code: code, Message: message, Cause: err})
			return
		}
		response := make([]browserWorkspaceResponse, 0, len(workspaces))
		for _, workspace := range workspaces {
			response = append(response, browserWorkspaceResponse{ID: workspace.ExternalWorkspaceID, Name: workspace.DisplayName})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("GET "+sessionPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || !principal.Known {
			httpresponse.WriteError(w, r, httpresponse.Failure{
				Status: http.StatusUnauthorized, Code: "identity.external.login_required", Message: "External login is required.",
			})
			return
		}
		roles, err := a.binding.assignedRoles(r.Context(), principal.WorkspaceID, principal.UserID)
		if err != nil {
			httpresponse.WriteError(w, r, httpresponse.Failure{
				Status: http.StatusServiceUnavailable, Code: "identity.external.session_unavailable", Message: "External session is unavailable.", Cause: err,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(browserSessionResponse{WorkspaceID: principal.WorkspaceID, SubjectID: principal.UserID, User: principal.User, Roles: roles, Permissions: principal.PermissionKeys(), AuthorizationRevision: principal.AuthorizationRevision, ExpiresAt: principal.AccessBundle.ExpiresAt, AccessBundle: principal.AccessBundle})
	})
	return mux
}
