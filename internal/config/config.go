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

const Version = "domainry-identity-bridge-config-v2"

type Config struct {
	Browser         *Browser         `json:"browser,omitempty"`
	Version         string           `json:"version"`
	InstallationID  string           `json:"installation_id"`
	ApplicationKey  string           `json:"application_key"`
	Provider        Provider         `json:"provider"`
	Workspace       Workspace        `json:"workspace"`
	ServiceSubjects []ServiceSubject `json:"service_subjects,omitempty"`
}

type Provider struct {
	Key          string       `json:"key"`
	Verification Verification `json:"verification"`
	Profile      *Profile     `json:"profile,omitempty"`
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
	Location string                `json:"location"`
	Name     string                `json:"name"`
	Prefix   string                `json:"prefix,omitempty"`
	Mirrors  []CredentialPlacement `json:"mirrors,omitempty"`
}

// CredentialPlacement repeats the same user credential in an additional
// header or cookie when an upstream contract requires both transports.
type CredentialPlacement struct {
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

// Profile optionally enriches a successfully verified external subject from a
// second provider endpoint. The returned subject ID must match the verified
// token subject before mutable display fields are accepted.
type Profile struct {
	Kind             string                     `json:"kind"`
	Endpoint         string                     `json:"endpoint"`
	Method           string                     `json:"method"`
	Timeout          string                     `json:"timeout"`
	MaxResponseBytes int64                      `json:"max_response_bytes"`
	Credential       Credential                 `json:"credential"`
	ServiceHeaders   map[string]SecretReference `json:"service_headers,omitempty"`
	Response         ProfileResponse            `json:"response"`
}

type ProfileResponse struct {
	SubjectID   string          `json:"subject_id"`
	DisplayName string          `json:"display_name,omitempty"`
	Email       string          `json:"email,omitempty"`
	Checks      []ResponseCheck `json:"checks"`
}

type Workspace struct {
	Mode                 string                  `json:"mode"`
	CreateOnFirstAccess  bool                    `json:"create_on_first_access"`
	NameTemplate         string                  `json:"name_template"`
	InitialRoleKeys      []string                `json:"initial_role_keys"`
	ApplicationBootstrap map[string]any          `json:"application_bootstrap,omitempty"`
	Selector             *WorkspaceSelector      `json:"selector,omitempty"`
	Membership           *MembershipVerification `json:"membership,omitempty"`
}

// WorkspaceSelector names the untrusted request header that selects one
// externally governed Workspace. MembershipVerification must authorize the
// verified subject for the selected value before it reaches persistence.
type WorkspaceSelector struct {
	Location string `json:"location"`
	Name     string `json:"name"`
}

type MembershipVerification struct {
	Kind             string                     `json:"kind"`
	Endpoint         string                     `json:"endpoint"`
	Method           string                     `json:"method"`
	Timeout          string                     `json:"timeout"`
	MaxResponseBytes int64                      `json:"max_response_bytes"`
	Credential       Credential                 `json:"credential"`
	ServiceHeaders   map[string]SecretReference `json:"service_headers,omitempty"`
	Response         MembershipResponse         `json:"response"`
}

type MembershipResponse struct {
	Items         string          `json:"items"`
	WorkspaceID   string          `json:"workspace_id"`
	WorkspaceName string          `json:"workspace_name,omitempty"`
	Checks        []ResponseCheck `json:"checks"`
}

type ServiceSubject struct {
	ID       string   `json:"id"`
	RoleKeys []string `json:"role_keys"`
}

// WorkspaceNameFields are the only identity fields available to naming templates.
type WorkspaceNameFields struct {
	DisplayName           string
	SubjectID             string
	ProviderKey           string
	ExternalWorkspaceID   string
	ExternalWorkspaceName string
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
	if err := validateHTTP("verification", verification.Endpoint, verification.Method, verification.Timeout, verification.MaxResponseBytes, verification.Credential, verification.ServiceHeaders); err != nil {
		return err
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
	if err := validateChecks("response", response.Checks); err != nil {
		return err
	}
	if profile := value.Provider.Profile; profile != nil {
		if profile.Kind != "http_profile" {
			return fmt.Errorf("profile.kind must be http_profile")
		}
		if err := validateHTTP("profile", profile.Endpoint, profile.Method, profile.Timeout, profile.MaxResponseBytes, profile.Credential, profile.ServiceHeaders); err != nil {
			return err
		}
		if profile.Response.SubjectID == "" || profile.Response.DisplayName == "" && profile.Response.Email == "" || len(profile.Response.Checks) == 0 {
			return fmt.Errorf("profile response requires subject_id, a display_name or email, and checks")
		}
		for _, pointer := range []string{profile.Response.SubjectID, profile.Response.DisplayName, profile.Response.Email} {
			if _, err := jsonpointer.Parts(pointer); err != nil {
				return fmt.Errorf("invalid profile response JSON pointer")
			}
		}
		if err := validateChecks("profile response", profile.Response.Checks); err != nil {
			return err
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
	workspace := value.Workspace
	if workspace.Mode != "per_user" && workspace.Mode != "per_external_group" {
		return fmt.Errorf("workspace.mode must be per_user or per_external_group")
	}
	if workspace.Mode == "per_user" {
		if workspace.Selector != nil || workspace.Membership != nil {
			return fmt.Errorf("per_user Workspace cannot configure selector or membership")
		}
	} else {
		if workspace.Selector == nil || workspace.Membership == nil {
			return fmt.Errorf("per_external_group Workspace requires selector and membership")
		}
		if workspace.Selector.Location != "header" || !headerKey.MatchString(workspace.Selector.Name) || !allowedHeader(workspace.Selector.Name) || strings.EqualFold(workspace.Selector.Name, "Authorization") {
			return fmt.Errorf("Workspace selector must use a non-reserved header")
		}
		if value.Browser != nil && value.Browser.Credential.Location == "header" && strings.EqualFold(value.Browser.Credential.Name, workspace.Selector.Name) {
			return fmt.Errorf("Workspace selector conflicts with browser credential header")
		}
		membership := workspace.Membership
		if membership.Kind != "http_membership_list" {
			return fmt.Errorf("membership.kind must be http_membership_list")
		}
		if err := validateHTTP("membership", membership.Endpoint, membership.Method, membership.Timeout, membership.MaxResponseBytes, membership.Credential, membership.ServiceHeaders); err != nil {
			return err
		}
		if membership.Response.Items == "" || membership.Response.WorkspaceID == "" || len(membership.Response.Checks) == 0 {
			return fmt.Errorf("membership response requires items, workspace_id, and checks")
		}
		for _, pointer := range []string{membership.Response.Items, membership.Response.WorkspaceID, membership.Response.WorkspaceName} {
			if _, err := jsonpointer.Parts(pointer); err != nil {
				return fmt.Errorf("invalid membership response JSON pointer")
			}
		}
		if err := validateChecks("membership response", membership.Response.Checks); err != nil {
			return err
		}
	}
	if len(workspace.InitialRoleKeys) == 0 {
		return fmt.Errorf("workspace.initial_role_keys is required")
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
	if _, err := workspace.RenderName(WorkspaceNameFields{DisplayName: "Example", SubjectID: "subject", ProviderKey: "provider", ExternalWorkspaceID: "group", ExternalWorkspaceName: "Example group"}); err != nil {
		return err
	}
	return nil
}

func validateHTTP(label, endpoint, method, timeoutValue string, maxResponseBytes int64, credential Credential, serviceHeaders map[string]SecretReference) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("%s.endpoint must be an HTTPS URL without credentials, query, or fragment", label)
	}
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("%s.method must be GET or POST", label)
	}
	timeout, err := time.ParseDuration(timeoutValue)
	if err != nil || timeout < time.Millisecond || timeout > 30*time.Second {
		return fmt.Errorf("%s.timeout must be between 1ms and 30s", label)
	}
	if maxResponseBytes < 1 || maxResponseBytes > 1024*1024 {
		return fmt.Errorf("%s.max_response_bytes must be between 1 and 1048576", label)
	}
	if err := validateCredentialPlacement(label, method, CredentialPlacement{Location: credential.Location, Name: credential.Name, Prefix: credential.Prefix}, true); err != nil {
		return err
	}
	placements := append([]CredentialPlacement{{Location: credential.Location, Name: credential.Name, Prefix: credential.Prefix}}, credential.Mirrors...)
	seenPlacements := map[string]bool{}
	for index, placement := range placements {
		if index > 0 {
			if err := validateCredentialPlacement(label+" credential mirror", method, placement, false); err != nil {
				return err
			}
		}
		key := placement.Location + "\x00" + placement.Name
		if placement.Location == "header" {
			key = placement.Location + "\x00" + strings.ToLower(placement.Name)
		}
		if seenPlacements[key] {
			return fmt.Errorf("%s credential placements must be unique", label)
		}
		seenPlacements[key] = true
	}
	seenHeaders := map[string]bool{}
	for name, secret := range serviceHeaders {
		key := strings.ToLower(name)
		if !headerKey.MatchString(name) || !allowedHeader(name) || seenHeaders[key] {
			return fmt.Errorf("%s service header name is reserved, invalid, or duplicated", label)
		}
		for _, placement := range placements {
			if placement.Location == "header" && strings.EqualFold(name, placement.Name) || placement.Location == "cookie" && key == "cookie" {
				return fmt.Errorf("%s service header conflicts with the user credential", label)
			}
		}
		if !environmentKey.MatchString(secret.Environment) || strings.ContainsAny(secret.Prefix, "\r\n") {
			return fmt.Errorf("%s service header requires a valid environment reference and prefix", label)
		}
		seenHeaders[key] = true
	}
	return nil
}

func validateCredentialPlacement(label, method string, credential CredentialPlacement, allowJSON bool) error {
	if strings.ContainsAny(credential.Prefix, "\r\n") {
		return fmt.Errorf("%s credential prefix contains a newline", label)
	}
	switch credential.Location {
	case "header", "cookie":
		if !headerKey.MatchString(credential.Name) {
			return fmt.Errorf("%s credential name must be a valid header or cookie name", label)
		}
		if credential.Location == "header" && !allowedHeader(credential.Name) {
			return fmt.Errorf("%s credential header is reserved", label)
		}
		if credential.Location == "cookie" && credential.Prefix != "" {
			return fmt.Errorf("%s cookie credentials do not support prefixes", label)
		}
	case "json":
		if !allowJSON {
			return fmt.Errorf("%s must use header or cookie", label)
		}
		if credential.Name == "" || strings.TrimSpace(credential.Name) != credential.Name || method != http.MethodPost {
			return fmt.Errorf("%s JSON credential requires a non-empty field name and POST", label)
		}
		if credential.Prefix != "" {
			return fmt.Errorf("%s JSON credentials do not support prefixes", label)
		}
	default:
		return fmt.Errorf("%s credential.location must be header, cookie, or json", label)
	}
	return nil
}

func validateChecks(label string, checks []ResponseCheck) error {
	for _, check := range checks {
		if check.Path == "" {
			return fmt.Errorf("%s check path is required", label)
		}
		if _, err := jsonpointer.Parts(check.Path); err != nil {
			return fmt.Errorf("invalid %s check JSON pointer", label)
		}
		decoder := json.NewDecoder(bytes.NewReader(check.Equals))
		decoder.UseNumber()
		var scalar any
		if decoder.Decode(&scalar) != nil || decoder.Decode(new(any)) != io.EOF {
			return fmt.Errorf("%s check equals must be one JSON scalar", label)
		}
		switch scalar.(type) {
		case string, bool, json.Number:
		default:
			return fmt.Errorf("%s check equals must be a string, boolean, or number", label)
		}
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

func (value Workspace) RenderName(fields WorkspaceNameFields) (string, error) {
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
