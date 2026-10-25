// Package module assembles the external identity bridge in the host process.
// It does not implement identity.Binding or misreport an Identity deployment mode.
package module

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/application"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	"github.com/domainry/domainry-identity-bridge/internal/provider"
	"github.com/domainry/domainry-identity-bridge/module/config"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/authorization"
)

const ContractVersion = bridge.ContractVersion

var (
	ErrCredentialRejected   = bridge.ErrCredentialRejected
	ErrProviderUnavailable  = bridge.ErrProviderUnavailable
	ErrProviderResponse     = bridge.ErrProviderResponse
	ErrWorkspaceSelection   = bridge.ErrWorkspaceSelection
	ErrWorkspaceMembership  = bridge.ErrWorkspaceMembership
	ErrWorkspaceUnavailable = bridge.ErrWorkspaceUnavailable
	ErrWorkspaceMismatch    = bridge.ErrWorkspaceMismatch
	ErrWorkspaceInactive    = bridge.ErrWorkspaceInactive
	ErrPolicyUnavailable    = bridge.ErrPolicyUnavailable
	ErrPolicyMismatch       = bridge.ErrPolicyMismatch
)

type ExternalSubject = bridge.ExternalSubject
type ExternalWorkspace = bridge.ExternalWorkspace
type WorkspaceRequest = bridge.WorkspaceRequest
type WorkspaceBinding = bridge.WorkspaceBinding
type WorkspaceAuthority = bridge.WorkspaceAuthority
type PolicyRequest = bridge.PolicyRequest
type PolicyAuthority = bridge.PolicyAuthority
type Host = bridge.Host

type Options struct {
	// Transport is host-owned and must preserve TLS verification in production.
	Transport         http.RoundTripper
	LookupEnvironment func(string) (string, bool)
	Now               func() time.Time
}

type Module struct{ service *application.Service }

func Open(cfg config.Config, host Host, options Options) (*Module, error) {
	if host.Workspaces == nil || host.Policies == nil {
		return nil, fmt.Errorf("bridge requires workspace and policy authorities")
	}
	// Validate and isolate configuration from caller mutations after composition.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid bridge configuration")
	}
	snapshot, err := config.Load(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	verifier, err := provider.New(snapshot.Provider, options.Transport, options.LookupEnvironment, now)
	if err != nil {
		return nil, err
	}
	var membership application.MembershipVerifier
	if snapshot.Workspace.Mode == "per_external_group" {
		membership, err = provider.NewMembership(*snapshot.Workspace.Membership, options.Transport, options.LookupEnvironment)
		if err != nil {
			return nil, err
		}
	}
	return &Module{service: &application.Service{Config: snapshot, Host: host, Verifier: verifier, Membership: membership, Now: now}}, nil
}

func (value *Module) Authenticate(ctx context.Context, credential string) (authorization.Principal, error) {
	principal, err := value.service.Authenticate(ctx, credential)
	if errors.Is(err, bridge.ErrWorkspaceSelection) || errors.Is(err, bridge.ErrWorkspaceMembership) {
		return authorization.Principal{}, &identity.Error{Class: identity.ErrorClassForbidden, Code: "identity.external_workspace_denied", Cause: err}
	}
	return principal, err
}

// WithSelectedWorkspace supplies an untrusted external Workspace candidate for
// non-HTTP callers. Authentication still verifies membership server-side.
func WithSelectedWorkspace(ctx context.Context, externalWorkspaceID string) context.Context {
	return application.WithSelectedWorkspace(ctx, externalWorkspaceID)
}

var _ authorization.PrincipalAuthenticator = (*Module)(nil)
