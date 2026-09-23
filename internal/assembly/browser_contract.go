package assembly

import (
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	identity "github.com/domainry/domainry-identity-sdk"
)

const (
	externalConfigPath  = "/auth/external/config"
	externalSessionPath = "/auth/external/session"
	externalClientPath  = "/auth/external/client.js"
)

type browserCredentialResponse struct {
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

type browserConfigResponse struct {
	Mode           string                     `json:"mode"`
	SessionPath    string                     `json:"session_path"`
	ApplicationKey string                     `json:"application_key"`
	DisplayName    string                     `json:"display_name,omitempty"`
	LoginURL       string                     `json:"login_url,omitempty"`
	LogoutURL      *string                    `json:"logout_url,omitempty"`
	Credential     *browserCredentialResponse `json:"credential,omitempty"`
}

type browserSessionResponse struct {
	WorkspaceID           string                 `json:"workspace_id"`
	SubjectID             string                 `json:"subject_id"`
	User                  identity.User          `json:"user"`
	Roles                 []identity.Role        `json:"roles"`
	Permissions           []string               `json:"permissions"`
	AuthorizationRevision string                 `json:"authorization_revision"`
	ExpiresAt             time.Time              `json:"expires_at"`
	AccessBundle          *identity.AccessBundle `json:"access_bundle"`
}

func externalAdapterRoutes() []modulehttp.Route {
	routes := make([]modulehttp.Route, 0, 3)
	for _, value := range []struct {
		key, path string
		strategy  actioncontract.AuthorizationStrategy
	}{
		{"config", externalConfigPath, actioncontract.AuthorizationAnonymous},
		{"client", externalClientPath, actioncontract.AuthorizationAnonymous},
		{"session", externalSessionPath, actioncontract.AuthorizationAuthenticated},
	} {
		routes = append(routes, modulehttp.Route{Action: actioncontract.ActionDefinition{
			Key: "identity.external." + value.key, Owner: "module:identity", SourceKind: "module_adapter",
			CapabilityKey: "identity.external", CapabilityLabel: "External identity", OperationKey: value.key,
			OperationLabel: value.key, Label: "External identity " + value.key,
			Exposures:     []actioncontract.Exposure{actioncontract.ExposurePublic, actioncontract.ExposureManagement},
			Authorization: actioncontract.Authorization{Strategy: value.strategy},
			HTTP:          &actioncontract.HTTPBinding{Method: "GET", RouteTemplate: value.path}, EffectClass: actioncontract.EffectRead,
			RiskLevel: actioncontract.RiskLow, IdempotencyDecision: "not_applicable", AuditClass: "identity_external", LifecycleStatus: actioncontract.LifecycleActive,
		}})
	}
	return routes
}
