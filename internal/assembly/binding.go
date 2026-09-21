package assembly

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/domainry/domainry-foundation/modulecapability"
	bridge "github.com/domainry/domainry-identity-bridge"
	bridgecapability "github.com/domainry/domainry-identity-bridge/capability"
	"github.com/domainry/domainry-identity-bridge/config"
	"github.com/domainry/domainry-identity-bridge/internal/application"
	"github.com/domainry/domainry-identity-bridge/internal/persistence"
	"github.com/domainry/domainry-identity-bridge/internal/provider"
	identity "github.com/domainry/domainry-identity-sdk"
)

type Binding struct {
	modulecapability.Binding
	Config      config.Config
	Application identity.ApplicationRef
	Store       *persistence.Store
	Service     *application.Service
	Now         func() time.Time
}

func Open(ctx context.Context, cfg config.Config, ref identity.ApplicationRef, handle identity.DatabaseHandle, transport http.RoundTripper, environment func(string) (string, bool), now func() time.Time) (*Binding, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if string(ref.ApplicationKey) != cfg.ApplicationKey || !ref.WorkspaceID.Valid() {
		return nil, fmt.Errorf("external identity application does not match configuration")
	}
	if now == nil {
		now = time.Now
	}
	verifier, err := provider.New(cfg.Provider, transport, environment, now)
	if err != nil {
		return nil, err
	}
	store, err := persistence.Open(ctx, handle)
	if err != nil {
		return nil, err
	}
	capabilities, err := bridgecapability.Open(bridgecapability.Inputs{})
	if err != nil {
		return nil, err
	}
	value := &Binding{Binding: capabilities, Config: cfg, Application: ref, Store: store, Now: now}
	value.Service = &application.Service{Config: cfg, Host: bridge.Host{Workspaces: value, Policies: value}, Verifier: verifier, Now: now}
	return value, nil
}

func (binding *Binding) Descriptor() identity.Descriptor {
	return identity.Descriptor{ProtocolVersion: identity.CurrentProtocolVersion, BundleVersion: identity.CurrentPolicyBundleVersion, AuthorizationVersion: identity.CurrentAuthorizationContractVersion,
		Mode: identity.DeploymentModeExternal, Issuer: binding.Config.Provider.Key, Audience: binding.Config.ApplicationKey, Capabilities: []string{"external_authentication", "personal_workspace", "directory_projection", "authorization", "permission_registry", "project_roles"}}
}
func (binding *Binding) PrincipalAuthenticator() identity.PrincipalAuthenticator {
	return binding
}
func (binding *Binding) Authenticate(ctx context.Context, credential string) (identity.Principal, error) {
	principal, err := binding.Service.Authenticate(ctx, credential)
	if err != nil {
		return identity.Principal{}, err
	}
	roles, err := binding.assignedRoles(ctx, principal.WorkspaceID, principal.UserID)
	if err != nil || len(roles) == 0 {
		return identity.Principal{}, denied()
	}
	principal.Roles = roles
	principal.RoleKey = roles[0].Key
	return principal, nil
}

func (binding *Binding) Authentication() identity.Authentication    { return authentication{binding} }
func (binding *Binding) Tokens() identity.TokenVerifier             { return authentication{binding} }
func (binding *Binding) Authorization() identity.Authorization      { return authorizationAdapter{binding} }
func (binding *Binding) Principals() identity.PrincipalResolver     { return binding }
func (binding *Binding) Projection() identity.Projection            { return projection{binding} }
func (binding *Binding) Applications() identity.ApplicationRegistry { return binding }
func (binding *Binding) Permissions() identity.PermissionRegistry   { return binding }
func (binding *Binding) Credentials() identity.CredentialManager    { return authentication{binding} }
func (binding *Binding) Close(context.Context) error                { return nil }

func unsupported() error {
	return &identity.Error{StatusCode: http.StatusNotImplemented, Code: "identity.external_capability_unavailable"}
}
func denied() error {
	return &identity.Error{StatusCode: http.StatusForbidden, Code: "identity.external_scope_denied"}
}

func (binding *Binding) namespace() string {
	return persistence.Key(binding.Config.InstallationID, binding.Config.Provider.Key)
}
func (binding *Binding) catalogKey(kind, owner string) string {
	return persistence.Key(binding.namespace(), binding.Config.ApplicationKey, kind, owner)
}
func (binding *Binding) checkApplication(ref identity.ApplicationRef) error {
	if ref.ApplicationKey != binding.Application.ApplicationKey || ref.WorkspaceID != binding.Application.WorkspaceID {
		return denied()
	}
	return nil
}

var _ identity.Binding = (*Binding)(nil)
var _ identity.PrincipalAuthenticationBinding = (*Binding)(nil)
var _ identity.ProjectRoleCatalogPublisher = (*Binding)(nil)
