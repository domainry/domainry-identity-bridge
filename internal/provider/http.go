// Package provider verifies opaque access credentials with a configured authority.
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
	"strconv"
	"strings"
	"time"

	bridge "github.com/domainry/domainry-identity-bridge"
	"github.com/domainry/domainry-identity-bridge/config"
	"github.com/domainry/domainry-identity-bridge/internal/jsonpointer"
)

type HTTP struct {
	key     string
	config  config.Verification
	client  *http.Client
	headers http.Header
	now     func() time.Time
}

func New(cfg config.Provider, transport http.RoundTripper, lookupEnv func(string) (string, bool), now func() time.Time) (*HTTP, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	if now == nil {
		now = time.Now
	}
	headers := make(http.Header)
	for name, reference := range cfg.Verification.ServiceHeaders {
		secret, found := lookupEnv(reference.Environment)
		if !found || strings.TrimSpace(secret) == "" || strings.ContainsAny(secret, "\r\n") {
			return nil, fmt.Errorf("bridge service credential environment reference is missing or invalid")
		}
		headers.Set(name, reference.Prefix+secret)
	}
	timeout, _ := time.ParseDuration(cfg.Verification.Timeout)
	return &HTTP{key: cfg.Key, config: cfg.Verification, headers: headers, now: now,
		client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (provider *HTTP) Verify(ctx context.Context, credential string) (bridge.ExternalSubject, error) {
	if strings.TrimSpace(credential) == "" || len(credential) > 32*1024 || strings.ContainsAny(credential, "\r\n") {
		return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
	}
	if err := ctx.Err(); err != nil {
		return bridge.ExternalSubject{}, err
	}
	var body io.Reader
	if provider.config.Credential.Location == "json" {
		encoded, _ := json.Marshal(map[string]string{provider.config.Credential.Name: credential})
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, provider.config.Method, provider.config.Endpoint, body)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderUnavailable
	}
	request.Header = provider.headers.Clone()
	request.Header.Set("Accept", "application/json")
	location := provider.config.Credential
	switch location.Location {
	case "header":
		request.Header.Set(location.Name, location.Prefix+credential)
	case "cookie":
		cookie := &http.Cookie{Name: location.Name, Value: credential}
		if err := cookie.Valid(); err != nil {
			return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
		}
		request.AddCookie(cookie)
	case "json":
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := provider.client.Do(request)
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
	raw, err := io.ReadAll(io.LimitReader(response.Body, provider.config.MaxResponseBytes+1))
	if err != nil || int64(len(raw)) > provider.config.MaxResponseBytes {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	for _, check := range provider.config.Response.Checks {
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
	subjectValue, found := jsonpointer.Get(document, provider.config.Response.SubjectID)
	if !found {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	subjectID, ok := opaqueID(subjectValue)
	if !ok {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	expiryValue, found := jsonpointer.Get(document, provider.config.Response.ExpiresAt)
	if !found {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	expiresAt, err := parseExpiry(expiryValue, provider.config.Response.ExpiryFormat)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	if !expiresAt.After(provider.now()) {
		return bridge.ExternalSubject{}, bridge.ErrCredentialRejected
	}
	displayName, err := optionalString(document, provider.config.Response.DisplayName)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	email, err := optionalString(document, provider.config.Response.Email)
	if err != nil {
		return bridge.ExternalSubject{}, bridge.ErrProviderResponse
	}
	return bridge.ExternalSubject{ProviderKey: provider.key, SubjectID: subjectID, DisplayName: displayName, Email: email, ExpiresAt: expiresAt}, nil
}

func opaqueID(value any) (string, bool) {
	var result string
	switch typed := value.(type) {
	case string:
		result = typed
	case json.Number:
		if _, err := typed.Int64(); err != nil {
			return "", false
		}
		result = typed.String()
	default:
		return "", false
	}
	return result, result != "" && result == strings.TrimSpace(result) && len(result) <= 512 && !strings.ContainsAny(result, "\x00\r\n")
}

func optionalString(document any, pointer string) (string, error) {
	if pointer == "" {
		return "", nil
	}
	value, found := jsonpointer.Get(document, pointer)
	if !found || value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok || len(text) > 1024 {
		return "", bridge.ErrProviderResponse
	}
	return strings.TrimSpace(text), nil
}

func parseExpiry(value any, format string) (time.Time, error) {
	if format == "rfc3339" {
		text, ok := value.(string)
		if !ok {
			return time.Time{}, bridge.ErrProviderResponse
		}
		return time.Parse(time.RFC3339, text)
	}
	var raw string
	switch typed := value.(type) {
	case json.Number:
		raw = typed.String()
	case string:
		raw = typed
	default:
		return time.Time{}, bridge.ErrProviderResponse
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 || seconds > 253402300799 {
		return time.Time{}, bridge.ErrProviderResponse
	}
	return time.Unix(seconds, 0).UTC(), nil
}
