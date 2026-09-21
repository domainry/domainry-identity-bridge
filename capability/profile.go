// Package capability exposes Identity Bridge's source-owned adaptation
// profile without opening the operational Identity SDK Binding.
package capability

import (
	"encoding/json"
	"strings"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulehttp"
	"github.com/domainry/domainry-identity-bridge/config"
	identity "github.com/domainry/domainry-identity-sdk"
)

const (
	ExternalAdapterProjectionKind = "identity.adapter_profile"
	ExternalAdapterProjectionKey  = "identity.external"
	ExternalConfigPath            = "/auth/external/config"
	ExternalSessionPath           = "/auth/external/session"
	ExternalClientPath            = "/auth/external/client.js"
)

type BrowserCredentialResponse struct {
	Location string `json:"location"`
	Name     string `json:"name,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

type BrowserConfigResponse struct {
	Mode           string                     `json:"mode"`
	SessionPath    string                     `json:"session_path"`
	ApplicationKey string                     `json:"application_key"`
	DisplayName    string                     `json:"display_name,omitempty"`
	LoginURL       string                     `json:"login_url,omitempty"`
	LogoutURL      *string                    `json:"logout_url,omitempty"`
	Credential     *BrowserCredentialResponse `json:"credential,omitempty"`
}

type BrowserSessionResponse struct {
	WorkspaceID           string                 `json:"workspace_id"`
	SubjectID             string                 `json:"subject_id"`
	User                  identity.User          `json:"user"`
	Roles                 []identity.Role        `json:"roles"`
	Permissions           []string               `json:"permissions"`
	AuthorizationRevision string                 `json:"authorization_revision"`
	ExpiresAt             time.Time              `json:"expires_at"`
	AccessBundle          *identity.AccessBundle `json:"access_bundle"`
}

// ExternalAdapterRoutes is the single route contract used by both the
// operational browser adapter and capability disclosure.
func ExternalAdapterRoutes() []modulehttp.Route {
	routes := []modulehttp.Route{}
	for _, value := range []struct {
		key, path string
		strategy  actioncontract.AuthorizationStrategy
	}{
		{"config", ExternalConfigPath, actioncontract.AuthorizationAnonymous},
		{"client", ExternalClientPath, actioncontract.AuthorizationAnonymous},
		{"session", ExternalSessionPath, actioncontract.AuthorizationAuthenticated},
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

// ExternalAdapterCategory combines the exact browser route contract and the
// machine configuration profile into one Identity-owned category. Human
// selection guidance is owned by capability/agent. A caller
// may attach this document to the canonical Identity capability binding or to
// the operational bridge binding; NewStaticBinding assigns its final module
// identity and digest.
func ExternalAdapterCategory() (modulecapability.CategoryDocument, error) {
	routes := ExternalAdapterRoutes()
	paths := map[string]map[string]json.RawMessage{}
	for _, route := range routes {
		action := route.Action
		workspaceScope := ""
		if action.Authorization.Strategy == actioncontract.AuthorizationAuthenticated {
			workspaceScope = "current"
		}
		responses := map[string]any{"200": map[string]any{"description": "Successful external identity response"}}
		switch action.Key {
		case "identity.external.config":
			responses["200"].(map[string]any)["content"] = jsonResponseSchema(BrowserConfigResponse{})
		case "identity.external.client":
			responses["200"].(map[string]any)["content"] = map[string]any{"text/javascript": map[string]any{"schema": map[string]any{"type": "string"}}}
		case "identity.external.session":
			responses["200"].(map[string]any)["content"] = jsonResponseSchema(BrowserSessionResponse{})
			responses["401"] = map[string]string{"description": "Authentication required"}
			responses["503"] = map[string]string{"description": "External session unavailable"}
		}
		operation, err := json.Marshal(map[string]any{
			"operationId": action.Key, "summary": action.Label,
			"responses": responses,
			modulecapability.OperationExtensionKey: modulecapability.OperationExtension{
				Owner: "identity", Authorization: modulecapability.Authorization{Strategy: action.Authorization.Strategy, WorkspaceScope: workspaceScope},
				Effect: modulecapability.EffectRead, Idempotency: modulecapability.Idempotency{Mode: action.IdempotencyDecision},
			},
		})
		if err != nil {
			return modulecapability.CategoryDocument{}, err
		}
		paths[action.HTTP.RouteTemplate] = map[string]json.RawMessage{strings.ToLower(action.HTTP.Method): operation}
	}
	profile, err := ExternalAdapterProfile()
	if err != nil {
		return modulecapability.CategoryDocument{}, err
	}
	return modulecapability.CategoryDocument{
		Category: modulecapability.CategorySummary{
			Key: "identity.external", Name: "External identity adapter",
			Description:    "Reuse an existing account authority with verified external subjects, personal Workspace ownership, application authorization, and browser session integration.",
			OperationCount: len(routes), AssemblyChains: []string{"identity_before_authorization_and_application_publication"},
		},
		OpenAPI:     modulecapability.OpenAPIFragment{OpenAPI: "3.1.0", Paths: paths},
		Projections: []modulecapability.SourceProjection{profile},
	}, nil
}

// ExternalAdapterProfile describes when and how the external Identity
// implementation is assembled. The JSON Schema is derived from Config so the
// disclosed field shape cannot drift from the configuration decoder; semantic
// constraints remain explicit because they are enforced by Config.Validate.
func ExternalAdapterProfile() (modulecapability.SourceProjection, error) {
	schema := modulecapability.JSONSchemaForGoValue(config.Config{})
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["title"] = "External Identity adapter configuration"
	schema["description"] = "Reuse an existing account authority while Domainry owns application authorization and one personal Workspace per external subject."

	property(schema, "version")["const"] = config.Version
	property(schema, "installation_id")["description"] = "Stable installation namespace. Changing it after deployment creates a different ownership namespace."
	property(schema, "application_key")["description"] = "Stable application key. Applications share personal Workspace ownership but keep application role assignment and bootstrap state separate."

	provider := property(schema, "provider")
	property(provider, "key")["description"] = "Stable provider namespace. Changing it after deployment creates a different ownership namespace."
	verification := property(provider, "verification")
	property(verification, "kind")["const"] = "http_introspection"
	property(verification, "endpoint")["format"] = "uri"
	property(verification, "endpoint")["description"] = "Absolute HTTPS credential-validation endpoint without credentials, query, or fragment."
	property(verification, "method")["enum"] = []string{"GET", "POST"}
	property(verification, "timeout")["description"] = "Go duration between 1ms and 30s."
	property(verification, "max_response_bytes")["minimum"] = 1
	property(verification, "max_response_bytes")["maximum"] = 1024 * 1024
	enrichCredential(property(verification, "credential"), true)
	property(verification, "service_headers")["description"] = "Optional server-only headers whose values are resolved from environment references; raw secrets are not configuration fields."
	response := property(verification, "response")
	for _, key := range []string{"subject_id", "display_name", "email", "expires_at"} {
		property(response, key)["description"] = "RFC 6901 JSON Pointer into the successful provider response."
	}
	property(response, "expiry_format")["enum"] = []string{"unix_seconds", "rfc3339"}
	checks := property(response, "checks")
	checks["minItems"] = 1
	checks["description"] = "All checks must match exactly; HTTP 200 alone never authenticates a subject."

	workspace := property(schema, "personal_workspace")
	property(workspace, "mode")["const"] = "per_user"
	property(workspace, "create_on_first_access")["description"] = "When true, first successful authentication creates the personal Workspace atomically with ownership, user projection, roles, and application bootstrap."
	property(workspace, "name_template")["description"] = "Template using only .DisplayName, .SubjectID, and .ProviderKey; output must contain 1 to 160 characters."
	property(workspace, "initial_role_keys")["minItems"] = 1
	property(workspace, "initial_role_keys")["uniqueItems"] = true
	property(workspace, "initial_role_keys")["description"] = "Application-published personal role keys assigned only when this application is first bound; later login does not overwrite assignments."
	property(workspace, "application_bootstrap")["description"] = "Application bootstrap input committed in the same host transaction as first Workspace creation."

	browser := property(schema, "browser")
	property(browser, "display_name")["minLength"] = 1
	for _, key := range []string{"login_url", "logout_url"} {
		property(browser, key)["format"] = "uri"
		property(browser, key)["description"] = "Absolute HTTPS navigation URL owned by the external account authority."
	}
	enrichCredential(property(browser, "credential"), false)
	property(browser, "allowed_origins")["minItems"] = 1
	property(browser, "allowed_origins")["uniqueItems"] = true
	property(browser, "allowed_origins")["description"] = "Exact HTTPS application origins allowed to use credential-bearing browser requests."

	property(schema, "service_subjects")["description"] = "Optional non-user workload subjects and their application role keys; these do not authenticate human users."

	schema["x-domainry-account-reuse"] = map[string]any{
		"ownership_key":             []string{"installation_id", "provider.key", "external_subject_id"},
		"application_key_excluded":  true,
		"workspace_reuse":           "The same external subject reuses one personal Workspace across applications in the same installation and provider namespace.",
		"application_scoped_state":  []string{"initial role assignment", "application bootstrap"},
		"credential_verification":   "Every authenticated request revalidates the presented credential with the configured external HTTPS endpoint.",
		"domainry_account_mutation": false,
	}
	schema["x-domainry-assembly"] = map[string]any{
		"topology_file":          "config/modules.json",
		"topology_value":         map[string]string{"IDENTITY_MODE": "external"},
		"configuration_file":     "config/identity-external.json",
		"configuration_override": "DOMAINRY_IDENTITY_BRIDGE_CONFIG_FILE",
		"browser_routes": []string{
			"GET " + ExternalConfigPath,
			"GET " + ExternalSessionPath,
			"GET " + ExternalClientPath,
		},
		"browser_integration": []string{
			"Load /auth/external/client.js or use the equivalent header credential flow",
			"Call session() to establish or restore the external subject's personal Workspace before business requests",
			"Use login() and logout() only as navigation to URLs actually supported by the external authority",
		},
	}
	schema["x-domainry-runtime-behavior"] = map[string]any{
		"atomic_first_access": []string{"Runtime Workspace", "external ownership", "Identity user projection", "initial application roles", "application bootstrap"},
		"authorization_owner": "Domainry Identity SDK policy evaluator using the application-published role catalog",
		"first_user_admin":    false,
		"secret_policy":       "Service header values are environment references; credentials and provider response bodies are not logged.",
	}
	schema["examples"] = []any{map[string]any{
		"version": config.Version, "installation_id": "example-installation", "application_key": "example-application",
		"provider": map[string]any{"key": "account-provider", "verification": map[string]any{
			"kind": "http_introspection", "endpoint": "https://accounts.example.com/passport/token/validate", "method": "POST", "timeout": "3s", "max_response_bytes": 65536,
			"credential": map[string]any{"location": "json", "name": "token"},
			"response": map[string]any{"subject_id": "/data/user_id", "display_name": "/data/email", "email": "/data/email", "expires_at": "/data/expires_at", "expiry_format": "unix_seconds", "checks": []any{
				map[string]any{"path": "/errCode", "equals": 0}, map[string]any{"path": "/data/valid", "equals": true}, map[string]any{"path": "/data/token_type", "equals": "access"},
			}},
		}},
		"personal_workspace": map[string]any{"mode": "per_user", "create_on_first_access": true, "name_template": "Personal workspace", "initial_role_keys": []string{"personal_owner"}},
		"browser":            map[string]any{"display_name": "Accounts", "login_url": "https://accounts.example.com/login", "logout_url": "https://accounts.example.com/logout", "credential": map[string]any{"location": "cookie", "name": "token"}, "allowed_origins": []string{"https://app.example.com"}},
	}}

	payload, err := json.Marshal(schema)
	if err != nil {
		return modulecapability.SourceProjection{}, err
	}
	return modulecapability.SourceProjection{Kind: ExternalAdapterProjectionKind, Key: ExternalAdapterProjectionKey, Payload: payload}, nil
}

func enrichCredential(schema map[string]any, provider bool) {
	locations := []string{"header", "cookie"}
	if provider {
		locations = append(locations, "json")
	}
	property(schema, "location")["enum"] = locations
	property(schema, "name")["minLength"] = 1
	property(schema, "prefix")["description"] = "Optional prefix for header credentials only; cookie and JSON credentials reject prefixes."
	if provider {
		schema["description"] = "How Runtime forwards the presented credential to the external validation endpoint. JSON credentials require POST."
	} else {
		schema["description"] = "How the browser sends the existing login credential to Runtime. Cookie mode requires a compatible origin; otherwise use the existing login SDK's header token."
	}
}

func property(schema map[string]any, key string) map[string]any {
	return schema["properties"].(map[string]any)[key].(map[string]any)
}

func jsonResponseSchema(value any) map[string]any {
	return map[string]any{"application/json": map[string]any{"schema": modulecapability.JSONSchemaForGoValue(value)}}
}
