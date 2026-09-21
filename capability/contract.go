package capability

import (
	"github.com/domainry/domainry-foundation/modulecapability"
)

func openContract(_ Inputs) (*modulecapability.StaticBinding, error) {
	category, err := ExternalAdapterCategory()
	if err != nil {
		return nil, err
	}
	return modulecapability.NewStaticBinding(modulecapability.ModuleSummary{
		Identity: modulecapability.ModuleIdentity{Key: "identity", SourceOwner: "domainry-identity-bridge", ModuleVersion: "0.1.0", ValidationRevision: "1", SupportedDeploymentModes: []modulecapability.DeploymentMode{modulecapability.DeploymentModeModule}},
		Name:     "External identity bridge", Description: "Reuse an external login authority with persistent personal workspace ownership.",
		Composition: modulecapability.ModuleComposition{ProvidedCapabilities: []string{"authentication", "authorization", "personal_workspace", "directory_projection"}, RequiredModules: []string{}, OptionalModules: []string{}, ConflictingModules: []string{}, AssemblyChains: []string{"identity_before_authorization_and_application_publication"}, ValidationScopes: []string{}},
	}, []modulecapability.CategoryDocument{category}, nil)
}
