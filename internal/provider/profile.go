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

type Profile struct {
	config  config.Profile
	client  *http.Client
	headers http.Header
}

func NewProfile(cfg config.Profile, transport http.RoundTripper, lookupEnv func(string) (string, bool)) (*Profile, error) {
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
			return nil, fmt.Errorf("bridge profile service credential environment reference is missing or invalid")
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
	}, "domainry.identity_bridge.profile", telemetry.HTTPClientInstrumentationOptions{DisableDiagnosticContent: true})
	return &Profile{config: cfg, client: client, headers: headers}, nil
}

func (profile *Profile) Lookup(ctx context.Context, credential, expectedSubjectID string) (bridge.ExternalSubject, error) {
	if strings.TrimSpace(credential) == "" || len(credential) > 32*1024 || strings.ContainsAny(credential, "\r\n") {
		return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
	}
	if err := ctx.Err(); err != nil {
		return bridge.ExternalSubject{}, err
	}
	var body io.Reader
	if profile.config.Credential.Location == "json" {
		encoded, _ := json.Marshal(map[string]string{profile.config.Credential.Name: credential})
		body = bytes.NewReader(encoded)
	} else if profile.config.Method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	ctx = telemetry.WithHTTPClientOperation(ctx, "identity_bridge.profile.lookup")
	request, err := http.NewRequestWithContext(ctx, profile.config.Method, profile.config.Endpoint, body)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderUnavailable
	}
	request.Header = profile.headers.Clone()
	request.Header.Set("Accept", "application/json")
	if err := applyCredential(request, profile.config.Credential, credential); err != nil {
		return bridge.ExternalSubject{}, err
	}
	if profile.config.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := profile.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return bridge.ExternalSubject{}, ctx.Err()
		}
		return bridge.ExternalSubject{}, bridge.ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
	}
	if response.StatusCode != http.StatusOK {
		return bridge.ExternalSubject{}, bridge.ErrProviderUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, profile.config.MaxResponseBytes+1))
	if err != nil || int64(len(raw)) > profile.config.MaxResponseBytes {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	for _, check := range profile.config.Response.Checks {
		actual, found := jsonpointer.Get(document, check.Path)
		if !found {
			return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
		}
		expectedDecoder := json.NewDecoder(bytes.NewReader(check.Equals))
		expectedDecoder.UseNumber()
		var expected any
		if expectedDecoder.Decode(&expected) != nil || !reflect.DeepEqual(expected, actual) {
			return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
		}
	}
	subjectValue, found := jsonpointer.Get(document, profile.config.Response.SubjectID)
	if !found {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	subjectID, ok := opaqueID(subjectValue)
	if !ok || subjectID != expectedSubjectID {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	displayName, err := optionalString(document, profile.config.Response.DisplayName)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	email, err := optionalString(document, profile.config.Response.Email)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	return bridge.ExternalSubject{SubjectID: subjectID, DisplayName: displayName, Email: email}, nil
}
