// Package config loads a strict, provider-neutral bridge configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/jsonpointer"
)

const Version = "domainry-identity-bridge-config-v1"

type Config struct {
	Browser           *Browser          `json:"browser,omitempty"`
	Version           string            `json:"version"`
	InstallationID    string            `json:"installation_id"`
	ApplicationKey    string            `json:"application_key"`
	Provider          Provider          `json:"provider"`
	PersonalWorkspace PersonalWorkspace `json:"personal_workspace"`
	ServiceSubjects   []ServiceSubject  `json:"service_subjects,omitempty"`
}

type Provider struct {
	Key          string       `json:"key"`
	Verification Verification `json:"verification"`
}

type Verification struct {
	Kind             string                     `json:"kind"`
	Endpoint         string                     `json:"endpoint"`
	Method           string                     `json:"method"`
	Timeout          string                     `json:"timeout"`
	MaxResponseBytes int64                      `json:"max_response_bytes"`
	Credential       Credential                 `json:"credential"`
	ServiceHeaders   map[string]SecretReference `json:"service_headers,omitempty"`
	Response         Response                   `json:"response"`
}

type Credential struct {
	Location string `json:"location"`
	Name     string `json:"name"`
	Prefix   string `json:"prefix,omitempty"`
}

// SecretReference is resolved at module open; raw secret values are never config fields.
type SecretReference struct {
	Environment string `json:"environment"`
	Prefix      string `json:"prefix,omitempty"`
}

type Response struct {
	SubjectID    string          `json:"subject_id"`
	DisplayName  string          `json:"display_name,omitempty"`
	Email        string          `json:"email,omitempty"`
	ExpiresAt    string          `json:"expires_at"`
	ExpiryFormat string          `json:"expiry_format"`
	Checks       []ResponseCheck `json:"checks"`
}

type ResponseCheck struct {
	Path   string          `json:"path"`
	Equals json.RawMessage `json:"equals"`
}

type PersonalWorkspace struct {
	Mode                 string         `json:"mode"`
	CreateOnFirstAccess  bool           `json:"create_on_first_access"`
	NameTemplate         string         `json:"name_template"`
	InitialRoleKeys      []string       `json:"initial_role_keys"`
	ApplicationBootstrap map[string]any `json:"application_bootstrap,omitempty"`
}

type ServiceSubject struct {
	ID       string   `json:"id"`
	RoleKeys []string `json:"role_keys"`
}

// WorkspaceNameFields are the only identity fields available to naming templates.
type WorkspaceNameFields struct {
	DisplayName string
	SubjectID   string
	ProviderKey string
}

func Load(reader io.Reader) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return Config{}, fmt.Errorf("read bridge configuration: invalid or oversized document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var value Config
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("decode bridge configuration: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Config{}, fmt.Errorf("bridge configuration must contain exactly one JSON document")
	}
	if err := value.Validate(); err != nil {
		return Config{}, err
	}
	return value, nil
}

var stableKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
var environmentKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var headerKey = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func (value Config) Validate() error {
	if value.Version != Version {
		return fmt.Errorf("unsupported configuration version")
	}
	for _, entry := range []struct{ name, value string }{{"installation_id", value.InstallationID}, {"application_key", value.ApplicationKey}, {"provider.key", value.Provider.Key}} {
		if !stableKey.MatchString(entry.value) {
			return fmt.Errorf("%s must be a non-empty stable key", entry.name)
		}
	}
	verification := value.Provider.Verification
	if verification.Kind != "http_introspection" {
		return fmt.Errorf("verification.kind must be http_introspection")
	}
	u, err := url.Parse(verification.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("verification.endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	if verification.Method != http.MethodGet && verification.Method != http.MethodPost {
		return fmt.Errorf("verification.method must be GET or POST")
	}
	timeout, err := time.ParseDuration(verification.Timeout)
	if err != nil || timeout < time.Millisecond || timeout > 30*time.Second {
		return fmt.Errorf("verification.timeout must be between 1ms and 30s")
	}
	if verification.MaxResponseBytes < 1 || verification.MaxResponseBytes > 1024*1024 {
		return fmt.Errorf("verification.max_response_bytes must be between 1 and 1048576")
	}
	credential := verification.Credential
	if strings.ContainsAny(credential.Prefix, "\r\n") {
		return fmt.Errorf("credential prefix contains a newline")
	}
	switch credential.Location {
	case "header", "cookie":
		if !headerKey.MatchString(credential.Name) {
			return fmt.Errorf("credential name must be a valid header or cookie name")
		}
		if credential.Location == "header" && !allowedHeader(credential.Name) {
			return fmt.Errorf("credential header is reserved")
		}
		if credential.Location == "cookie" && credential.Prefix != "" {
			return fmt.Errorf("cookie credentials do not support prefixes")
		}
	case "json":
		if credential.Name == "" || strings.TrimSpace(credential.Name) != credential.Name || verification.Method != http.MethodPost {
			return fmt.Errorf("JSON credential requires a non-empty field name and POST")
		}
		if credential.Prefix != "" {
			return fmt.Errorf("JSON credentials do not support prefixes")
		}
	default:
		return fmt.Errorf("credential.location must be header, cookie, or json")
	}
	seenHeaders := map[string]bool{}
	for name, secret := range verification.ServiceHeaders {
		key := strings.ToLower(name)
		if !headerKey.MatchString(name) || !allowedHeader(name) || seenHeaders[key] {
			return fmt.Errorf("service header name is reserved, invalid, or duplicated")
		}
		if credential.Location == "header" && strings.EqualFold(name, credential.Name) || credential.Location == "cookie" && key == "cookie" {
			return fmt.Errorf("service header conflicts with the user credential")
		}
		if !environmentKey.MatchString(secret.Environment) || strings.ContainsAny(secret.Prefix, "\r\n") {
			return fmt.Errorf("service header requires a valid environment reference and prefix")
		}
		seenHeaders[key] = true
	}
	response := verification.Response
	if response.SubjectID == "" || response.ExpiresAt == "" || len(response.Checks) == 0 {
		return fmt.Errorf("response requires subject_id, expires_at, and explicit success/active checks")
	}
	for _, pointer := range []string{response.SubjectID, response.ExpiresAt, response.DisplayName, response.Email} {
		if _, err := jsonpointer.Parts(pointer); err != nil {
			return fmt.Errorf("invalid response field JSON pointer")
		}
	}
	if response.ExpiryFormat != "unix_seconds" && response.ExpiryFormat != "rfc3339" {
		return fmt.Errorf("response.expiry_format must be unix_seconds or rfc3339")
	}
	for _, check := range response.Checks {
		if check.Path == "" {
			return fmt.Errorf("response check path is required")
		}
		if _, err := jsonpointer.Parts(check.Path); err != nil {
			return fmt.Errorf("invalid response check JSON pointer")
		}
		decoder := json.NewDecoder(bytes.NewReader(check.Equals))
		decoder.UseNumber()
		var scalar any
		if decoder.Decode(&scalar) != nil || decoder.Decode(new(any)) != io.EOF {
			return fmt.Errorf("response check equals must be one JSON scalar")
		}
		switch scalar.(type) {
		case string, bool, json.Number:
		default:
			return fmt.Errorf("response check equals must be a string, boolean, or number")
		}
	}
	if value.Browser != nil {
		if err := value.Browser.Validate(); err != nil {
			return err
		}
	}
	serviceIDs := map[string]bool{}
	for _, subject := range value.ServiceSubjects {
		if strings.TrimSpace(subject.ID) != subject.ID || subject.ID == "" || len(subject.ID) > 255 || serviceIDs[subject.ID] || strings.HasPrefix(subject.ID, "user_") {
			return fmt.Errorf("service subject IDs must be unique and outside the personal-user namespace")
		}
		serviceIDs[subject.ID] = true
		keys := map[string]bool{}
		if len(subject.RoleKeys) == 0 {
			return fmt.Errorf("service subject roles are required")
		}
		for _, key := range subject.RoleKeys {
			if !stableKey.MatchString(key) || keys[key] {
				return fmt.Errorf("service role keys must be unique stable keys")
			}
			keys[key] = true
		}
	}
	workspace := value.PersonalWorkspace
	if workspace.Mode != "per_user" {
		return fmt.Errorf("personal_workspace.mode must be per_user; shared ownership is not implemented")
	}
	if len(workspace.InitialRoleKeys) == 0 {
		return fmt.Errorf("personal_workspace.initial_role_keys is required")
	}
	roles := map[string]bool{}
	for _, role := range workspace.InitialRoleKeys {
		if !stableKey.MatchString(role) || roles[role] {
			return fmt.Errorf("initial role keys must be unique stable keys")
		}
		roles[role] = true
	}
	if strings.TrimSpace(workspace.NameTemplate) == "" || len(workspace.NameTemplate) > 512 {
		return fmt.Errorf("workspace name template must be non-empty and at most 512 bytes")
	}
	if _, err := workspace.RenderName(WorkspaceNameFields{DisplayName: "Example", SubjectID: "subject", ProviderKey: "provider"}); err != nil {
		return err
	}
	return nil
}

func allowedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "content-type", "accept", "trailer", "upgrade", "te":
		return false
	default:
		return true
	}
}

func (value PersonalWorkspace) RenderName(fields WorkspaceNameFields) (string, error) {
	tmpl, err := template.New("workspace").Option("missingkey=error").Parse(value.NameTemplate)
	if err != nil {
		return "", fmt.Errorf("invalid workspace name template")
	}
	var result bytes.Buffer
	if err := tmpl.Execute(&result, fields); err != nil {
		return "", fmt.Errorf("workspace name template references unsupported fields")
	}
	name := strings.TrimSpace(result.String())
	if name == "" || len([]rune(name)) > 160 {
		return "", fmt.Errorf("workspace name must contain 1 to 160 characters")
	}
	return name, nil
}
