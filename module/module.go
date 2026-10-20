// Package module assembles the external identity bridge in the host process.
// It does not implement identity.Binding or misreport an Identity deployment mode.
package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/application"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	"github.com/domainry/domainry-identity-bridge/internal/provider"
	"github.com/domainry/domainry-identity-bridge/module/config"
	"github.com/domainry/domainry-identity-sdk/authorization"
)

const ContractVersion = bridge.ContractVersion

var (
	ErrCredentialRejected   = bridge.ErrCredentialRejected
	ErrProviderUnavailable  = bridge.ErrProviderUnavailable
	ErrProviderResponse     = bridge.ErrProviderResponse
	ErrWorkspaceUnavailable = bridge.ErrWorkspaceUnavailable
	ErrWorkspaceMismatch    = bridge.ErrWorkspaceMismatch
	ErrWorkspaceInactive    = bridge.ErrWorkspaceInactive
	ErrPolicyUnavailable    = bridge.ErrPolicyUnavailable
	ErrPolicyMismatch       = bridge.ErrPolicyMismatch
)

type ExternalSubject = bridge.ExternalSubject
type PersonalWorkspaceRequest = bridge.PersonalWorkspaceRequest
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
	return &Module{service: &application.Service{Config: snapshot, Host: host, Verifier: verifier, Now: now}}, nil
}

func (value *Module) Authenticate(ctx context.Context, credential string) (authorization.Principal, error) {
	return value.service.Authenticate(ctx, credential)
}

var _ authorization.PrincipalAuthenticator = (*Module)(nil)
