package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity-bridge/internal/config"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	"github.com/domainry/domainry-identity-bridge/internal/jsonpointer"
)

// Membership verifies one selected external Workspace against the current
// user's credential. It deliberately ignores provider roles: Domainry roles
// remain code-published and application-owned.
type Membership struct {
	config  config.MembershipVerification
	client  *http.Client
	headers http.Header
}

func NewMembership(cfg config.MembershipVerification, transport http.RoundTripper, lookupEnv func(string) (string, bool)) (*Membership, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	headers := make(http.Header)
	for name, reference := range cfg.ServiceHeaders {
		secret, found := lookupEnv(reference.Environment)
		if !found || strings.TrimSpace(secret) == "" || strings.ContainsAny(secret, "\r\n") {
			return nil, fmt.Errorf("bridge membership service credential environment reference is missing or invalid")
		}
		headers.Set(name, reference.Prefix+secret)
	}
	timeout, _ := time.ParseDuration(cfg.Timeout)
	client := telemetry.InstrumentHTTPClientWithOptions(&http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, "domainry.identity_bridge.membership", telemetry.HTTPClientInstrumentationOptions{DisableDiagnosticContent: true})
	return &Membership{config: cfg, client: client, headers: headers}, nil
}

func (provider *Membership) VerifyMembership(ctx context.Context, credential, selectedWorkspaceID string) (bridge.ExternalWorkspace, error) {
	if selectedWorkspaceID == "" || selectedWorkspaceID != strings.TrimSpace(selectedWorkspaceID) || len(selectedWorkspaceID) > 512 || strings.ContainsAny(selectedWorkspaceID, "\x00\r\n") {
		return bridge.ExternalWorkspace{}, bridge.ErrWorkspaceSelection
	}
	workspaces, err := provider.ExternalWorkspaces(ctx, credential)
	if err != nil {
		return bridge.ExternalWorkspace{}, err
	}
	for _, workspace := range workspaces {
		if workspace.ExternalWorkspaceID == selectedWorkspaceID {
			return workspace, nil
		}
	}
	return bridge.ExternalWorkspace{}, bridge.ErrWorkspaceMembership
}

// ExternalWorkspaces returns only groups confirmed by the configured membership
// authority for the supplied credential. It intentionally omits provider roles.
func (provider *Membership) ExternalWorkspaces(ctx context.Context, credential string) ([]bridge.ExternalWorkspace, error) {
	if strings.TrimSpace(credential) == "" || len(credential) > 32*1024 || strings.ContainsAny(credential, "\r\n") {
		return nil, bridge.ErrCredentialRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var body io.Reader
	if provider.config.Credential.Location == "json" {
		encoded, _ := json.Marshal(map[string]string{provider.config.Credential.Name: credential})
		body = bytes.NewReader(encoded)
	} else if provider.config.Method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	ctx = telemetry.WithHTTPClientOperation(ctx, "identity_bridge.membership.verify")
	request, err := http.NewRequestWithContext(ctx, provider.config.Method, provider.config.Endpoint, body)
	if err != nil {
		return nil, bridge.ErrProviderUnavailable
	}
	request.Header = provider.headers.Clone()
	request.Header.Set("Accept", "application/json")
	if err := applyCredential(request, provider.config.Credential, credential); err != nil {
		return nil, err
	}
	if provider.config.Credential.Location == "json" {
		request.Header.Set("Content-Type", "application/json")
	}
	if provider.config.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := provider.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, bridge.ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, bridge.ErrCredentialRejected
	}
	if response.StatusCode != http.StatusOK {
		return nil, bridge.ErrProviderUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, provider.config.MaxResponseBytes+1))
	if err != nil || int64(len(raw)) > provider.config.MaxResponseBytes {
		return nil, bridge.ErrProviderResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, bridge.ErrProviderResponse
	}
	for _, check := range provider.config.Response.Checks {
		actual, found := jsonpointer.Get(document, check.Path)
		if !found {
			return nil, bridge.ErrCredentialRejected
		}
		expectedDecoder := json.NewDecoder(bytes.NewReader(check.Equals))
		expectedDecoder.UseNumber()
		var expected any
		if expectedDecoder.Decode(&expected) != nil || !reflect.DeepEqual(expected, actual) {
			return nil, bridge.ErrCredentialRejected
		}
	}
	itemsValue, found := jsonpointer.Get(document, provider.config.Response.Items)
	if !found {
		return nil, bridge.ErrProviderResponse
	}
	items, ok := itemsValue.([]any)
	if !ok {
		return nil, bridge.ErrProviderResponse
	}
	workspaces := make([]bridge.ExternalWorkspace, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		idValue, found := jsonpointer.Get(item, provider.config.Response.WorkspaceID)
		if !found {
			return nil, bridge.ErrProviderResponse
		}
		id, ok := opaqueID(idValue)
		if !ok {
			return nil, bridge.ErrProviderResponse
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, bridge.ErrProviderResponse
		}
		seen[id] = struct{}{}
		name, err := optionalString(item, provider.config.Response.WorkspaceName)
		if err != nil {
			return nil, bridge.ErrProviderResponse
		}
		workspaces = append(workspaces, bridge.ExternalWorkspace{ExternalWorkspaceID: id, DisplayName: name})
	}
	return workspaces, nil
}
