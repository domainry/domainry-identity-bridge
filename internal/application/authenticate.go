package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/config"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	"github.com/domainry/domainry-identity-sdk/authorization"
)

type Verifier interface {
	Verify(context.Context, string) (bridge.ExternalSubject, error)
}

type MembershipVerifier interface {
	VerifyMembership(context.Context, string, string) (bridge.ExternalWorkspace, error)
	ExternalWorkspaces(context.Context, string) ([]bridge.ExternalWorkspace, error)
}

type Service struct {
	Config     config.Config
	Host       bridge.Host
	Verifier   Verifier
	Membership MembershipVerifier
	Now        func() time.Time
}

// ExternalWorkspaces validates the credential with the identity authority
// before asking the membership authority which external groups it belongs to.
func (service *Service) ExternalWorkspaces(ctx context.Context, credential string) ([]bridge.ExternalWorkspace, error) {
	if service.Config.Workspace.Mode != "per_external_group" || service.Membership == nil {
		return nil, bridge.ErrWorkspaceSelection
	}
	subject, err := service.Verifier.Verify(ctx, credential)
	if err != nil {
		return nil, err
	}
	if subject.ProviderKey != service.Config.Provider.Key || subject.SubjectID == "" || !subject.ExpiresAt.After(service.Now()) {
		return nil, bridge.ErrCredentialRejected
	}
	return service.Membership.ExternalWorkspaces(ctx, credential)
}

func (service *Service) Authenticate(ctx context.Context, credential string) (authorization.Principal, error) {
	subject, err := service.Verifier.Verify(ctx, credential)
	if err != nil {
		return authorization.Principal{}, err
	}
	if subject.ProviderKey != service.Config.Provider.Key || subject.SubjectID == "" || !subject.ExpiresAt.After(service.Now()) {
		return authorization.Principal{}, bridge.ErrCredentialRejected
	}
	externalWorkspace := bridge.ExternalWorkspace{ExternalWorkspaceID: subject.SubjectID, DisplayName: subject.DisplayName}
	if service.Config.Workspace.Mode == "per_external_group" {
		selected, ok := SelectedWorkspace(ctx)
		if !ok || service.Membership == nil {
			return authorization.Principal{}, bridge.ErrWorkspaceSelection
		}
		externalWorkspace, err = service.Membership.VerifyMembership(ctx, credential, selected)
		if err != nil {
			return authorization.Principal{}, err
		}
	}
	name, err := service.Config.Workspace.RenderName(config.WorkspaceNameFields{
		DisplayName: subject.DisplayName, SubjectID: subject.SubjectID, ProviderKey: subject.ProviderKey,
		ExternalWorkspaceID: externalWorkspace.ExternalWorkspaceID, ExternalWorkspaceName: externalWorkspace.DisplayName,
	})
	if err != nil {
		return authorization.Principal{}, bridge.ErrProviderResponse
	}
	request := bridge.WorkspaceRequest{
		InstallationID: service.Config.InstallationID, ApplicationKey: service.Config.ApplicationKey,
		ProviderKey: subject.ProviderKey, ExternalWorkspaceID: externalWorkspace.ExternalWorkspaceID, ExternalSubjectID: subject.SubjectID,
		DisplayName: subject.DisplayName, Email: subject.Email,
		IdempotencyKey: workspaceKey(service.Config.InstallationID, subject.ProviderKey, externalWorkspace.ExternalWorkspaceID),
		Name:           name, InitialRoleKeys: append([]string(nil), service.Config.Workspace.InitialRoleKeys...),
		CreateIfMissing: service.Config.Workspace.CreateOnFirstAccess,
	}
	if err := ctx.Err(); err != nil {
		return authorization.Principal{}, err
	}
	workspace, err := service.Host.Workspaces.ResolveWorkspace(ctx, request)
	if err != nil {
		return authorization.Principal{}, bridge.ErrWorkspaceUnavailable
	}
	if workspace.InstallationID != request.InstallationID || workspace.ProviderKey != request.ProviderKey || workspace.ExternalWorkspaceID != request.ExternalWorkspaceID || workspace.ExternalSubjectID != request.ExternalSubjectID ||
		!validID(workspace.WorkspaceID) || strings.EqualFold(workspace.WorkspaceID, "default") || !validID(workspace.UserID) {
		return authorization.Principal{}, bridge.ErrWorkspaceMismatch
	}
	if !workspace.Active {
		return authorization.Principal{}, bridge.ErrWorkspaceInactive
	}
	bundle, err := service.Host.Policies.ResolveAccess(ctx, bridge.PolicyRequest{ApplicationKey: service.Config.ApplicationKey, Workspace: workspace})
	if err != nil {
		return authorization.Principal{}, bridge.ErrPolicyUnavailable
	}
	now := service.Now()
	if err := ctx.Err(); err != nil {
		return authorization.Principal{}, err
	}
	if !subject.ExpiresAt.After(now) {
		return authorization.Principal{}, bridge.ErrCredentialRejected
	}
	if err := bundle.Validate(now); err != nil {
		return authorization.Principal{}, bridge.ErrPolicyUnavailable
	}
	if string(bundle.Subject.WorkspaceID) != workspace.WorkspaceID || string(bundle.Subject.SubjectID) != workspace.UserID {
		return authorization.Principal{}, bridge.ErrPolicyMismatch
	}
	// Detach all nested policy slices from the host's potentially cached snapshot.
	raw, err := json.Marshal(bundle)
	if err != nil {
		return authorization.Principal{}, bridge.ErrPolicyUnavailable
	}
	var snapshot authorization.AccessBundle
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return authorization.Principal{}, bridge.ErrPolicyUnavailable
	}
	if subject.ExpiresAt.Before(snapshot.ExpiresAt) {
		snapshot.ExpiresAt = subject.ExpiresAt
	}
	principal := authorization.Principal{
		ContractVersion: authorization.PrincipalContextContractVersion, Known: true,
		WorkspaceID: workspace.WorkspaceID, UserID: workspace.UserID,
		AuthorizationRevision: string(snapshot.AuthorizationRevision), AccessBundle: &snapshot,
		OrgID: snapshot.Subject.OrgID, OrgScopeIDs: append([]string(nil), snapshot.Subject.OrgScopeIDs...),
		SupportOrgID: snapshot.Subject.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), snapshot.Subject.SupportOrgScopeIDs...),
		User: authorization.User{UserID: workspace.UserID, Name: subject.DisplayName, Email: subject.Email, Status: "active"},
	}
	for _, id := range snapshot.Subject.ReportingScopeUserIDs {
		principal.ReportingScopeUserIDs = append(principal.ReportingScopeUserIDs, string(id))
	}
	principal.Permissions = principal.PermissionKeys()
	return principal, nil
}

func validID(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func workspaceKey(installationID, providerKey, externalWorkspaceID string) string {
	// A tuple avoids ambiguous string concatenation. ApplicationKey is deliberately
	// excluded: a second application must not allocate another external Workspace.
	raw, _ := json.Marshal([]string{bridge.ContractVersion, installationID, providerKey, externalWorkspaceID})
	digest := sha256.Sum256(raw)
	return "external-workspace:" + hex.EncodeToString(digest[:])
}
