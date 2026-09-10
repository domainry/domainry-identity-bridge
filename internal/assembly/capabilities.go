package assembly

import (
	"encoding/json"
	"github.com/domainry/domainry-foundation/modulecapability"
	"strings"
)

func capabilityBinding() (*modulecapability.StaticBinding, error) {
	category := modulecapability.CategorySummary{Key: "external_identity", Name: "External identity", Description: "Verified external subjects, personal workspaces and application authorization.", AssemblyChains: []string{"external_identity"}}
	routes := browserAdapter{}.Routes()
	paths := map[string]map[string]json.RawMessage{}
	for _, route := range routes {
		a := route.Action
		workspaceScope := ""
		if a.Authorization.Strategy == "authenticated" {
			workspaceScope = "current"
		}
		operation, err := json.Marshal(map[string]any{"operationId": a.Key, "summary": a.Label, "responses": map[string]any{"200": map[string]string{"description": "Successful external identity response"}}, modulecapability.OperationExtensionKey: modulecapability.OperationExtension{Owner: "identity", Authorization: modulecapability.Authorization{Strategy: a.Authorization.Strategy, WorkspaceScope: workspaceScope}, Effect: modulecapability.EffectRead, Idempotency: modulecapability.Idempotency{Mode: a.IdempotencyDecision}}})
		if err != nil {
			return nil, err
		}
		paths[a.HTTP.RouteTemplate] = map[string]json.RawMessage{strings.ToLower(a.HTTP.Method): operation}
	}
	category.OperationCount = len(routes)
	return modulecapability.NewStaticBinding(modulecapability.ModuleSummary{
		Identity: modulecapability.ModuleIdentity{Key: "identity", SourceOwner: "domainry-identity-bridge", ModuleVersion: "0.1.0", ValidationRevision: "1", SupportedDeploymentModes: []modulecapability.DeploymentMode{modulecapability.DeploymentModeModule}},
		Name:     "External identity bridge", Description: "Reuse an external login authority with persistent personal workspace ownership.",
		Scenarios: modulecapability.AdaptationScenarios{SelectionExamples: []modulecapability.ScenarioExample{{Requirement: "Reuse existing login", Reason: "External provider owns account authentication"}}, RejectionExamples: []modulecapability.ScenarioExample{{Requirement: "Manage passwords locally", Reason: "Account mutations belong to the external authority"}}, UseWhen: []string{"An existing authority owns accounts and login."}, DoNotUseWhen: []string{"Local password or organization administration is required."}, RequirementSignals: []string{"external_identity"}, ProvidedCapabilities: []string{"authentication", "authorization", "personal_workspace", "directory_projection"}, AssemblyChains: []string{"external_identity"}},
	}, []modulecapability.CategoryDocument{{Category: category, OpenAPI: modulecapability.OpenAPIFragment{OpenAPI: "3.1.0", Paths: paths}, Projections: []modulecapability.SourceProjection{{Kind: "identity_adapter", Key: "external", Payload: json.RawMessage(`{"mode":"external","workspace_mode":"per_user","account_mutation":false}`)}}}}, nil)
}
