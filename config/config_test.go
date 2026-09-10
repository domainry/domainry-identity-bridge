package config_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/domainry/domainry-identity-bridge/config"
)

func example(t *testing.T) config.Config {
	t.Helper()
	file, err := os.Open("../examples/personal.config.json")
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
		{"shared ownership", func(c *config.Config) { c.PersonalWorkspace.Mode = "per_team" }},
		{"missing roles", func(c *config.Config) { c.PersonalWorkspace.InitialRoleKeys = nil }},
		{"duplicate roles", func(c *config.Config) { c.PersonalWorkspace.InitialRoleKeys = []string{"owner", "owner"} }},
		{"unknown name variable", func(c *config.Config) { c.PersonalWorkspace.NameTemplate = "{{.Password}}" }},
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
	cfg.PersonalWorkspace.NameTemplate = "{{.DisplayName}} / {{.SubjectID}}"
	cfg.PersonalWorkspace.InitialRoleKeys = []string{"project_user"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	name, err := cfg.PersonalWorkspace.RenderName(config.WorkspaceNameFields{DisplayName: "Alex", SubjectID: "42"})
	if err != nil || name != "Alex / 42" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}
