#!/usr/bin/env bash
set -euo pipefail
bridge_root="$(cd "$(dirname "$0")/.." && pwd)"
projects_root="$(dirname "$bridge_root")"
sdk_root="${IDENTITY_SDK_REPO_ROOT:-$projects_root/domainry-identity-sdk}"
mode="${1:-check}"
workspace_dir="$(mktemp -d "${TMPDIR:-/tmp}/identity-bridge-workspace.XXXXXX")"
trap 'rm -rf "$workspace_dir"' EXIT
modules=("$bridge_root" "$sdk_root")
if [[ "$mode" == runtime || "$mode" == plane ]]; then
  runtime_root="${RUNTIME_REPO_ROOT:-$projects_root/domainry-runtime}"
  modules+=("$runtime_root")
  for name in domainry-agent domainry-agent-sdk domainry-identity domainry-connectors; do
    if [[ -f "$projects_root/$name/go.mod" ]]; then modules+=("$projects_root/$name"); fi
  done
fi
if [[ "$mode" == plane ]]; then modules+=("${PLANE_REPO_ROOT:-$projects_root/domainry-plane}"); fi
for module in "${modules[@]}"; do
  [[ -f "$module/go.mod" ]] || { echo "Required source module missing: $module" >&2; exit 1; }
done
(cd "$workspace_dir" && GOWORK=off go work init "${modules[@]}")
export GOWORK="$workspace_dir/go.work"
case "$mode" in
  check)
    cd "$bridge_root"
    go test -race ./...
    go vet ./...
    go run ./cmd/identity-bridge -config examples/personal.config.json
    go run ./cmd/identity-bridge -config examples/browser.config.json
    go run ./cmd/identity-bridge -config examples/token-validation.config.json
    node --test web/client.test.js
    ;;
  runtime)
    cd "$runtime_root"
    go test -race -tags external_identity_integration ./pkg/runtimehost -run TestExternalIdentityRealRuntime -timeout 90s
    if go list -deps ./pkg/runtimehost | rg '^github.com/domainry/domainry-identity/'; then
      echo 'External Runtime imports Identity implementation' >&2
      exit 1
    fi
    ;;
  plane)
    cd "${PLANE_REPO_ROOT:-$projects_root/domainry-plane}"
    go test ./internal/controlplane/domaincodegen ./internal/builder/sourcefinalizer ./internal/controlplane/delivery ./internal/builder/projectdeliverybinding -run 'Test(ExternalIdentity|BindingContainsOnlyBackendApplicationIdentity)' -timeout 90s
    ;;
  *) echo 'Usage: scripts/verify.sh [check|runtime|plane]' >&2; exit 2 ;;
esac
