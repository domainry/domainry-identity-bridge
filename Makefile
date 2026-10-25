.PHONY: check integration-check config-check

RUNTIME_REPO_ROOT ?= ../domainry-runtime
PLANE_REPO_ROOT ?= ../domainry-plane

check:
	GOWORK=off go test -race ./...
	GOWORK=off go vet ./...
	GOWORK=off go run ./cmd/identity-bridge -config docs/examples/personal.config.json
	GOWORK=off go run ./cmd/identity-bridge -config docs/examples/browser.config.json
	GOWORK=off go run ./cmd/identity-bridge -config docs/examples/token-validation.config.json
	GOWORK=off go run ./cmd/identity-bridge -config docs/examples/external-group.config.json
	node --test internal/transport/browser/web/client.test.js

integration-check:
	cd $(RUNTIME_REPO_ROOT) && GOWORK=off go test -race -tags external_identity_integration ./pkg/runtimehost -run TestExternalIdentityRealRuntime -timeout 90s
	cd $(PLANE_REPO_ROOT) && GOWORK=off go test ./internal/controlplane/domaincodegen ./internal/builder/sourcefinalizer ./internal/controlplane/delivery ./internal/builder/projectdeliverybinding -run 'Test(ExternalIdentity|BindingContainsOnlyBackendApplicationIdentity)' -timeout 90s

config-check:
	GOWORK=off go run ./cmd/identity-bridge -config docs/examples/token-validation.config.json
