package capability

import (
	"encoding/json"
	"testing"

	"github.com/domainry/domainry-identity-bridge/config"
)

func TestExternalAdapterProfileDisclosesImplementedReuseAndAssemblyContract(t *testing.T) {
	profile, err := ExternalAdapterProfile()
	if err != nil {
		t.Fatal(err)
	}
	if profile.Kind != ExternalAdapterProjectionKind || profile.Key != ExternalAdapterProjectionKey {
		t.Fatalf("profile identity = %s/%s", profile.Kind, profile.Key)
	}
	var schema map[string]any
	if err := json.Unmarshal(profile.Payload, &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	version := properties["version"].(map[string]any)
	if version["const"] != config.Version {
		t.Fatalf("config version = %#v", version["const"])
	}
	if _, duplicated := schema["x-domainry-selection"]; duplicated {
		t.Fatal("machine profile must not duplicate human selection guidance")
	}
	reuse := schema["x-domainry-account-reuse"].(map[string]any)
	if reuse["application_key_excluded"] != true || reuse["domainry_account_mutation"] != false {
		t.Fatalf("reuse contract = %#v", reuse)
	}
	assembly := schema["x-domainry-assembly"].(map[string]any)
	if assembly["topology_file"] != "config/modules.json" || assembly["configuration_file"] != "config/identity-external.json" {
		t.Fatalf("assembly contract = %#v", assembly)
	}
}

func TestExternalAdapterCategoryUsesTheOperationalBrowserRoutes(t *testing.T) {
	category, err := ExternalAdapterCategory()
	if err != nil {
		t.Fatal(err)
	}
	routes := ExternalAdapterRoutes()
	if category.Category.OperationCount != len(routes) || len(category.OpenAPI.Paths) != len(routes) {
		t.Fatalf("category routes=%d/%d operational routes=%d", category.Category.OperationCount, len(category.OpenAPI.Paths), len(routes))
	}
	for _, route := range routes {
		methods := category.OpenAPI.Paths[route.Action.HTTP.RouteTemplate]
		if methods == nil {
			t.Fatalf("disclosure omits operational route %s", route.Pattern())
		}
		var operation map[string]any
		if err := json.Unmarshal(methods["get"], &operation); err != nil {
			t.Fatal(err)
		}
		responses, _ := operation["responses"].(map[string]any)
		success, _ := responses["200"].(map[string]any)
		if success["content"] == nil {
			t.Fatalf("route %s omits its implemented success response shape", route.Pattern())
		}
	}
}
