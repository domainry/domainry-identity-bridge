// Package bridge defines the host boundary for an external identity adapter.
// It reuses Identity SDK authorization contracts without importing Identity's implementation.
package bridge

import (
	"context"
	"errors"
	"time"

	"github.com/domainry/domainry-identity-sdk/authorization"
)

const ContractVersion = "domainry-identity-bridge-v2"

var (
	ErrCredentialRejected   = errors.New("bridge.credential_rejected")
	ErrProviderUnavailable  = errors.New("bridge.provider_unavailable")
	ErrProviderResponse     = errors.New("bridge.provider_response_invalid")
	ErrWorkspaceSelection   = errors.New("bridge.workspace_selection_required")
	ErrWorkspaceMembership  = errors.New("bridge.workspace_membership_rejected")
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

// ExternalWorkspace is returned only after the configured membership authority
// confirms that the verified subject belongs to the selected external group.
// Provider display fields are presentation facts, never authorization grants.
type ExternalWorkspace struct {
	ExternalWorkspaceID string
	DisplayName         string
}

// WorkspaceRequest binds one verified subject into an externally governed
// Workspace. The external Workspace selector is already membership-verified;
// it is never accepted directly from a client at this boundary.
// ApplicationKey scopes initial role definitions, not Workspace uniqueness.
type WorkspaceRequest struct {
	InstallationID      string
	ApplicationKey      string
	ProviderKey         string
	ExternalWorkspaceID string
	ExternalSubjectID   string
	DisplayName         string
	Email               string
	IdempotencyKey      string
	Name                string
	InitialRoleKeys     []string
	CreateIfMissing     bool
}

type WorkspaceBinding struct {
	InstallationID      string
	ProviderKey         string
	ExternalWorkspaceID string
	ExternalSubjectID   string
	WorkspaceID         string
	UserID              string
	Active              bool
}

// WorkspaceAuthority owns durable uniqueness and provisioning. Resolve must:
//   - serialize creation by (InstallationID, ProviderKey, ExternalWorkspaceID);
//   - bind each ExternalSubjectID to a distinct user inside that Workspace;
//   - atomically commit Workspace, membership, initial roles, and bootstrap data;
//   - return the existing binding on retries without resetting roles;
//   - return suspended bindings as inactive, never replace or reactivate them;
//   - reject missing bindings when CreateIfMissing is false.
//
// Credentials never cross this boundary. External members receive no installation authority.
type WorkspaceAuthority interface {
	ResolveWorkspace(context.Context, WorkspaceRequest) (WorkspaceBinding, error)
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
