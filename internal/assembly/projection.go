package assembly

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/domainry/domainry-foundation/requestcontext"
	identity "github.com/domainry/domainry-identity-sdk"
)

type projection struct{ binding *Binding }

func (adapter projection) scope(ctx context.Context) (string, error) {
	workspace := requestcontext.WorkspaceID(ctx)
	if workspace == "" {
		if principal, ok := identity.PrincipalFromContext(ctx); ok {
			workspace = principal.WorkspaceID
		}
	}
	if workspace == "" {
		return "", denied()
	}
	if principal, ok := identity.PrincipalFromContext(ctx); ok && principal.WorkspaceID != workspace {
		return "", denied()
	}
	active, err := adapter.binding.Store.Host.ExternalWorkspaceActive(ctx, workspace)
	if err != nil {
		return "", err
	}
	if !active {
		return "", denied()
	}
	return workspace, nil
}

func (adapter projection) FindUser(ctx context.Context, request identity.UserLookup) (identity.User, bool, error) {
	workspace, err := adapter.scope(ctx)
	if err != nil {
		return identity.User{}, false, err
	}
	users, err := adapter.users(ctx, workspace)
	if err != nil {
		return identity.User{}, false, err
	}
	for _, user := range users {
		if user.ID == string(request.UserID) {
			return user, true, nil
		}
	}
	return identity.User{}, false, nil
}
func (adapter projection) users(ctx context.Context, workspace string) ([]identity.User, error) {
	records, err := adapter.binding.Store.List(ctx, adapter.binding.namespace(), "owner", workspace)
	if err != nil {
		return nil, err
	}
	result := []identity.User{}
	for _, record := range records {
		var owner ownership
		if err := json.Unmarshal(record.Payload, &owner); err != nil {
			return nil, err
		}
		if owner.Binding.Active {
			if _, err := adapter.binding.assignment(ctx, owner); err == nil {
				result = append(result, owner.User)
			} else {
				var deniedError *identity.Error
				if !errors.As(err, &deniedError) || deniedError.Code != "identity.external_scope_denied" {
					return nil, err
				}
			}
		}
	}
	return result, nil
}
func (adapter projection) ListUsers(ctx context.Context, request identity.ProjectionQuery) ([]identity.User, error) {
	workspace, err := adapter.scope(ctx)
	if err != nil {
		return nil, err
	}
	return adapter.users(ctx, workspace)
}
func (adapter projection) FindOrganizationUnit(ctx context.Context, request identity.OrganizationUnitLookup) (identity.OrganizationUnit, bool, error) {
	if _, err := adapter.scope(ctx); err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	return identity.OrganizationUnit{}, false, nil
}
func (adapter projection) ListRoles(ctx context.Context, request identity.ProjectionQuery) ([]identity.Role, error) {
	if _, err := adapter.scope(ctx); err != nil {
		return nil, err
	}
	catalog, err := adapter.binding.roles(ctx, adapter.binding.Store.DB)
	if err != nil {
		return nil, err
	}
	roles := []identity.Role{}
	for _, role := range catalog.Roles {
		roles = append(roles, identity.Role{ID: role.Key, Key: role.Key, Label: role.Name, Status: "active"})
	}
	return roles, nil
}
func (adapter projection) ListUserRoleAssignments(ctx context.Context, request identity.UserRoleAssignmentQuery) ([]identity.UserRoleAssignment, error) {
	workspace, err := adapter.scope(ctx)
	if err != nil {
		return nil, err
	}
	users, err := adapter.users(ctx, workspace)
	if err != nil {
		return nil, err
	}
	result := []identity.UserRoleAssignment{}
	for _, user := range users {
		if request.UserID != "" && string(request.UserID) != user.ID {
			continue
		}
		roles, err := adapter.binding.assignedRoles(ctx, workspace, user.ID)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			result = append(result, identity.UserRoleAssignment{UserID: user.ID, RoleID: role.ID, Source: "external_personal_owner"})
		}
	}
	return result, nil
}

func (binding *Binding) Resolve(ctx context.Context, request identity.PrincipalResolutionRequest) (identity.PrincipalResolution, error) {
	workspace := requestcontext.WorkspaceID(ctx)
	if workspace == "" {
		if principal, ok := identity.PrincipalFromContext(ctx); ok {
			workspace = principal.WorkspaceID
		}
	}
	if workspace == "" {
		return identity.PrincipalResolution{}, denied()
	}
	if principal, ok := identity.PrincipalFromContext(ctx); ok && principal.WorkspaceID != workspace {
		return identity.PrincipalResolution{}, denied()
	}
	user := string(request.SubjectID)
	var roles []string
	isService := false
	for _, subject := range binding.Config.ServiceSubjects {
		if subject.ID == user {
			roles = subject.RoleKeys
			isService = true
			break
		}
	}
	var profile identity.User
	if !isService {
		owner, err := binding.ownerForUser(ctx, workspace, user)
		if err != nil {
			return identity.PrincipalResolution{}, err
		}
		assigned, err := binding.assignment(ctx, owner)
		if err != nil {
			return identity.PrincipalResolution{}, err
		}
		roles = assigned.RoleKeys
		profile = owner.User
	} else {
		profile = identity.User{ID: user, Name: user, Status: "active", AccountType: "service"}
	}
	if request.RoleKey != "" {
		if !includes(roles, request.RoleKey) {
			return identity.PrincipalResolution{}, denied()
		}
		roles = []string{request.RoleKey}
	}
	bundle, err := binding.bundle(ctx, workspace, user, roles, isService)
	if err != nil {
		return identity.PrincipalResolution{}, err
	}
	principal := identity.Principal{ContractVersion: identity.PrincipalContextContractVersion, Known: true, WorkspaceID: workspace, UserID: user, User: profile, AuthorizationRevision: string(bundle.AuthorizationRevision), AccessBundle: &bundle}
	if len(roles) > 0 {
		principal.RoleKey = roles[0]
	}
	if !isService {
		principal.Roles, err = binding.assignedRoles(ctx, workspace, user)
		if err != nil {
			return identity.PrincipalResolution{}, err
		}
	}
	principal.Permissions = principal.PermissionKeys()
	return identity.PrincipalResolution{Principal: principal, AccessBundle: bundle}, nil
}
