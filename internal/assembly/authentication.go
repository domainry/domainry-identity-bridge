package assembly

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type authentication struct{ binding *Binding }

func (adapter authentication) CurrentSession(ctx context.Context, request identity.CurrentSessionRequest) (identity.SessionView, error) {
	p, err := adapter.binding.Service.Authenticate(ctx, request.AccessToken)
	if err != nil {
		return identity.SessionView{}, err
	}
	roles, err := adapter.binding.assignedRoles(ctx, p.WorkspaceID, p.UserID)
	if err != nil {
		return identity.SessionView{}, err
	}
	result := identity.SessionView{WorkspaceID: identity.WorkspaceID(p.WorkspaceID), SubjectID: identity.SubjectID(p.UserID), AuthorizationRevision: identity.AuthorizationRevision(p.AuthorizationRevision), User: p.User, Roles: roles, Permissions: p.PermissionKeys()}
	if len(roles) > 0 {
		result.DefaultRole = roles[0].Key
	}
	return result, nil
}

func (adapter authentication) Verify(ctx context.Context, request identity.VerifyTokenRequest) (identity.VerifiedToken, error) {
	if request.Audience != "" && string(request.Audience) != adapter.binding.Config.ApplicationKey || request.Issuer != "" && request.Issuer != adapter.binding.Config.Provider.Key {
		return identity.VerifiedToken{}, denied()
	}
	p, err := adapter.binding.Service.Authenticate(ctx, request.AccessToken)
	if err != nil {
		return identity.VerifiedToken{}, err
	}
	return identity.VerifiedToken{Issuer: adapter.binding.Config.Provider.Key, Audience: identity.ApplicationKey(adapter.binding.Config.ApplicationKey), SubjectID: identity.SubjectID(p.UserID), WorkspaceID: identity.WorkspaceID(p.WorkspaceID), AuthorizationRevision: identity.AuthorizationRevision(p.AuthorizationRevision), ExpiresAt: p.AccessBundle.ExpiresAt.Unix()}, nil
}

// Account mutation and provider login protocols remain owned by the external
// authority. Capability discovery and the bridge browser API direct clients there.
func (authentication) Providers(context.Context, identity.ProviderQuery) ([]identity.Provider, error) {
	return nil, unsupported()
}
func (authentication) LoginWithPassword(context.Context, identity.PasswordLoginRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, unsupported()
}
func (authentication) BeginFederatedLogin(context.Context, identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	return identity.ProviderChallenge{}, unsupported()
}
func (authentication) CompleteFederatedLogin(context.Context, identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	return identity.FederatedLoginCompletion{}, unsupported()
}
func (authentication) ExchangeAuthorizationCode(context.Context, identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, unsupported()
}
func (authentication) VerifyOTP(context.Context, identity.VerifyOTPRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, unsupported()
}
func (authentication) RefreshSession(context.Context, identity.RefreshRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, unsupported()
}
func (authentication) LogoutSession(context.Context, identity.LogoutRequest) error {
	return unsupported()
}
func (authentication) ChangePassword(context.Context, identity.ChangePasswordRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, unsupported()
}
func (authentication) ResetPassword(context.Context, identity.ResetPasswordRequest) error {
	return unsupported()
}
func (authentication) RevokeSessions(context.Context, identity.RevokeSessionsRequest) error {
	return unsupported()
}
