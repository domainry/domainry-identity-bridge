package config_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/domainry/domainry-identity-bridge/internal/config"
)

func example(t *testing.T) config.Config {
	t.Helper()
	file, err := os.Open("../../docs/examples/personal.config.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfigurationRejectsIncompleteAndAmbiguousTrust(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*config.Config)
	}{
		{"unknown protocol", func(c *config.Config) { c.Provider.Verification.Kind = "unimplemented" }},
		{"insecure endpoint", func(c *config.Config) { c.Provider.Verification.Endpoint = "http://accounts.example.com/verify" }},
		{"secret URL", func(c *config.Config) {
			c.Provider.Verification.Endpoint = "https://user:secret@accounts.example.com/verify"
		}},
		{"query credential", func(c *config.Config) { c.Provider.Verification.Endpoint += "?token=secret" }},
		{"unbounded timeout", func(c *config.Config) { c.Provider.Verification.Timeout = "0s" }},
		{"missing checks", func(c *config.Config) { c.Provider.Verification.Response.Checks = nil }},
		{"missing expiry", func(c *config.Config) { c.Provider.Verification.Response.ExpiresAt = "" }},
		{"bad pointer", func(c *config.Config) { c.Provider.Verification.Response.SubjectID = "/invalid~2escape" }},
		{"object condition", func(c *config.Config) { c.Provider.Verification.Response.Checks[0].Equals = json.RawMessage(`{}`) }},
		{"null condition", func(c *config.Config) { c.Provider.Verification.Response.Checks[0].Equals = json.RawMessage(`null`) }},
		{"secret header collision", func(c *config.Config) {
			c.Provider.Verification.ServiceHeaders["authorization"] = config.SecretReference{Environment: "APP_SECRET"}
		}},
		{"duplicate header", func(c *config.Config) {
			c.Provider.Verification.ServiceHeaders["x-application-credential"] = config.SecretReference{Environment: "APP_SECRET"}
		}},
		{"transport header", func(c *config.Config) { c.Provider.Verification.Credential.Name = "Host" }},
		{"header injection", func(c *config.Config) { c.Provider.Verification.Credential.Prefix = "Bearer\r\nInjected: " }},
		{"GET JSON credential", func(c *config.Config) {
			c.Provider.Verification.Method = "GET"
			c.Provider.Verification.Credential.Location = "json"
		}},
		{"shared ownership", func(c *config.Config) { c.Workspace.Mode = "per_team" }},
		{"missing roles", func(c *config.Config) { c.Workspace.InitialRoleKeys = nil }},
		{"duplicate roles", func(c *config.Config) { c.Workspace.InitialRoleKeys = []string{"owner", "owner"} }},
		{"unknown name variable", func(c *config.Config) { c.Workspace.NameTemplate = "{{.Password}}" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := example(t)
			test.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	cfg := example(t)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`, string(raw) + ` {}`, string(raw) + ` garbage`} {
		if _, err := config.Load(strings.NewReader(input)); err == nil {
			t.Fatal("expected strict decoding failure")
		}
	}
}

func TestNamesAndProviderFieldsAreConfiguration(t *testing.T) {
	cfg := example(t)
	cfg.Provider.Key = "custom-accounts"
	cfg.Provider.Verification.Endpoint = "https://identity.example.net/validate-session"
	cfg.Provider.Verification.Credential = config.Credential{Location: "cookie", Name: "custom_session"}
	cfg.Provider.Verification.Response.SubjectID = "/result/users/0/account~1id"
	cfg.Workspace.NameTemplate = "{{.DisplayName}} / {{.SubjectID}}"
	cfg.Workspace.InitialRoleKeys = []string{"project_user"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	name, err := cfg.Workspace.RenderName(config.WorkspaceNameFields{DisplayName: "Alex", SubjectID: "42"})
	if err != nil || name != "Alex / 42" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}

func TestExternalGroupWorkspaceRequiresBoundedMembershipVerification(t *testing.T) {
	cfg := example(t)
	cfg.Workspace.Mode = "per_external_group"
	cfg.Workspace.NameTemplate = "{{.ExternalWorkspaceName}} knowledge"
	cfg.Workspace.Selector = &config.WorkspaceSelector{Location: "header", Name: "X-Group-ID"}
	cfg.Workspace.Membership = &config.MembershipVerification{
		Kind: "http_membership_list", Endpoint: "https://accounts.example.net/groups", Method: "POST", Timeout: "3s", MaxResponseBytes: 65536,
		Credential: config.Credential{Location: "header", Name: "Authorization", Prefix: "Bearer ", Mirrors: []config.CredentialPlacement{{Location: "cookie", Name: "token"}}},
		Response: config.MembershipResponse{
			Items: "/data/groups", WorkspaceID: "/group_id", WorkspaceName: "/name",
			Checks: []config.ResponseCheck{{Path: "/errCode", Equals: json.RawMessage(`0`)}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	name, err := cfg.Workspace.RenderName(config.WorkspaceNameFields{ExternalWorkspaceName: "Research"})
	if err != nil || name != "Research knowledge" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	for _, mutate := range []func(*config.Config){
		func(c *config.Config) { c.Workspace.Selector = nil },
		func(c *config.Config) { c.Workspace.Membership = nil },
		func(c *config.Config) { c.Workspace.Selector.Name = "Authorization" },
		func(c *config.Config) { c.Workspace.Membership.Endpoint = "http://accounts.example.net/groups" },
		func(c *config.Config) { c.Workspace.Membership.Response.Items = "/bad~2pointer" },
		func(c *config.Config) { c.Workspace.Membership.Response.Checks = nil },
		func(c *config.Config) {
			c.Workspace.Membership.Credential.Mirrors = []config.CredentialPlacement{{Location: "json", Name: "token"}}
		},
		func(c *config.Config) {
			c.Workspace.Membership.Credential.Mirrors = []config.CredentialPlacement{{Location: "header", Name: "authorization", Prefix: "Bearer "}}
		},
	} {
		candidate := cfg
		selector := *cfg.Workspace.Selector
		membership := *cfg.Workspace.Membership
		candidate.Workspace.Selector = &selector
		candidate.Workspace.Membership = &membership
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid external group configuration was accepted")
		}
	}
}

func TestProfileEnrichmentRequiresBoundedSubjectBinding(t *testing.T) {
	validProfile := func() *config.Profile {
		return &config.Profile{
			Kind: "http_profile", Endpoint: "https://accounts.example.net/passport/inner/user/info", Method: "GET", Timeout: "3s", MaxResponseBytes: 65536,
			Credential: config.Credential{Location: "cookie", Name: "token"},
			Response: config.ProfileResponse{
				SubjectID: "/data/user_id", DisplayName: "/data/user_name", Email: "/data/email",
				Checks: []config.ResponseCheck{{Path: "/errCode", Equals: json.RawMessage(`0`)}},
			},
		}
	}
	cfg := example(t)
	cfg.Provider.Profile = validProfile()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config.Profile){
		func(profile *config.Profile) { profile.Kind = "unimplemented" },
		func(profile *config.Profile) { profile.Endpoint = "http://accounts.example.net/profile" },
		func(profile *config.Profile) { profile.Response.SubjectID = "" },
		func(profile *config.Profile) { profile.Response.DisplayName, profile.Response.Email = "", "" },
		func(profile *config.Profile) { profile.Response.Checks = nil },
		func(profile *config.Profile) { profile.Response.Email = "/bad~2pointer" },
		func(profile *config.Profile) { profile.Credential = config.Credential{Location: "json", Name: "token"} },
	} {
		candidate := example(t)
		candidate.Provider.Profile = validProfile()
		mutate(candidate.Provider.Profile)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid profile configuration was accepted")
		}
	}
}
