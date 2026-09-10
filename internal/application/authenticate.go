package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	bridge "github.com/domainry/domainry-identity-bridge"
	"github.com/domainry/domainry-identity-bridge/config"
	"github.com/domainry/domainry-identity-sdk/authorization"
)

type Verifier interface {
	Verify(context.Context, string) (bridge.ExternalSubject, error)
}

type Service struct {
	Config   config.Config
	Host     bridge.Host
	Verifier Verifier
	Now      func() time.Time
}

func (service *Service) Authenticate(ctx context.Context, credential string) (authorization.Principal, error) {
	subject, err := service.Verifier.Verify(ctx, credential)
	if err != nil {
		return authorization.Principal{}, err
	}
	if subject.ProviderKey != service.Config.Provider.Key || subject.SubjectID == "" || !subject.ExpiresAt.After(service.Now()) {
		return authorization.Principal{}, bridge.ErrCredentialRejected
	}
	name, err := service.Config.PersonalWorkspace.RenderName(config.WorkspaceNameFields{DisplayName: subject.DisplayName, SubjectID: subject.SubjectID, ProviderKey: subject.ProviderKey})
	if err != nil {
		return authorization.Principal{}, bridge.ErrProviderResponse
	}
	request := bridge.PersonalWorkspaceRequest{
		InstallationID: service.Config.InstallationID, ApplicationKey: service.Config.ApplicationKey,
		ProviderKey: subject.ProviderKey, ExternalSubjectID: subject.SubjectID,
		DisplayName: subject.DisplayName, Email: subject.Email,
		IdempotencyKey: personalWorkspaceKey(service.Config.InstallationID, subject.ProviderKey, subject.SubjectID),
		Name:           name, InitialRoleKeys: append([]string(nil), service.Config.PersonalWorkspace.InitialRoleKeys...),
		CreateIfMissing: service.Config.PersonalWorkspace.CreateOnFirstAccess,
	}
	if err := ctx.Err(); err != nil {
		return authorization.Principal{}, err
	}
	workspace, err := service.Host.Workspaces.ResolvePersonalWorkspace(ctx, request)
	if err != nil {
		return authorization.Principal{}, bridge.ErrWorkspaceUnavailable
	}
	if workspace.InstallationID != request.InstallationID || workspace.ProviderKey != request.ProviderKey || workspace.ExternalSubjectID != request.ExternalSubjectID ||
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
		User: authorization.User{ID: workspace.UserID, Name: subject.DisplayName, Email: subject.Email, Status: "active"},
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

func personalWorkspaceKey(installationID, providerKey, subjectID string) string {
	// A tuple avoids ambiguous string concatenation. ApplicationKey is deliberately
	// excluded: a second application must not allocate another personal Workspace.
	raw, _ := json.Marshal([]string{bridge.ContractVersion, installationID, providerKey, subjectID})
	digest := sha256.Sum256(raw)
	return "personal-workspace:" + hex.EncodeToString(digest[:])
}
