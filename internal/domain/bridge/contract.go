// Package bridge defines the host boundary for an external identity adapter.
// It reuses Identity SDK authorization contracts without importing Identity's implementation.
package bridge

import (
	"context"
	"errors"
	"time"

	"github.com/domainry/domainry-identity-sdk/authorization"
)

const ContractVersion = "domainry-identity-bridge-v1"

var (
	ErrCredentialRejected   = errors.New("bridge.credential_rejected")
	ErrProviderUnavailable  = errors.New("bridge.provider_unavailable")
	ErrProviderResponse     = errors.New("bridge.provider_response_invalid")
	ErrWorkspaceUnavailable = errors.New("bridge.workspace_unavailable")
	ErrWorkspaceMismatch    = errors.New("bridge.workspace_identity_mismatch")
	ErrWorkspaceInactive    = errors.New("bridge.workspace_inactive")
	ErrPolicyUnavailable    = errors.New("bridge.policy_unavailable")
	ErrPolicyMismatch       = errors.New("bridge.policy_identity_mismatch")
)

// ExternalSubject is returned only after the configured authority verifies the
// credential. Source IDs are opaque strings, including numeric IDs larger than 2^53.
type ExternalSubject struct {
	ProviderKey string
	SubjectID   string
	DisplayName string
	Email       string
	ExpiresAt   time.Time
}

// PersonalWorkspaceRequest contains no client-selected Workspace or owner ID.
// ApplicationKey scopes initial role definitions, not personal ownership uniqueness.
type PersonalWorkspaceRequest struct {
	InstallationID    string
	ApplicationKey    string
	ProviderKey       string
	ExternalSubjectID string
	DisplayName       string
	Email             string
	IdempotencyKey    string
	Name              string
	InitialRoleKeys   []string
	CreateIfMissing   bool
}

type WorkspaceBinding struct {
	InstallationID    string
	ProviderKey       string
	ExternalSubjectID string
	WorkspaceID       string
	UserID            string
	Active            bool
}

// WorkspaceAuthority owns durable uniqueness and provisioning. Resolve must:
//   - serialize creation by (InstallationID, ProviderKey, ExternalSubjectID);
//   - atomically commit Workspace, ownership, initial roles, and bootstrap data;
//   - return the existing binding on retries without resetting roles;
//   - return suspended bindings as inactive, never replace or reactivate them;
//   - reject missing bindings when CreateIfMissing is false.
//
// Credentials never cross this boundary. Personal owners receive no installation authority.
type WorkspaceAuthority interface {
	ResolvePersonalWorkspace(context.Context, PersonalWorkspaceRequest) (WorkspaceBinding, error)
}

type PolicyRequest struct {
	ApplicationKey string
	Workspace      WorkspaceBinding
}

// PolicyAuthority resolves current application-specific policy for the exact
// binding. Its bundle must exclude installation administration and other applications.
// Policy changes are authoritative here; initial role configuration is not reapplied on login.
type PolicyAuthority interface {
	ResolveAccess(context.Context, PolicyRequest) (authorization.AccessBundle, error)
}

type Host struct {
	Workspaces WorkspaceAuthority
	Policies   PolicyAuthority
}
