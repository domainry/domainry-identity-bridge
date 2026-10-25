package application

import (
	"context"
	"strings"
)

type selectedWorkspaceKey struct{}

// WithSelectedWorkspace carries an untrusted external Workspace selector to
// Authenticate. The configured membership verifier must still authorize it.
func WithSelectedWorkspace(ctx context.Context, externalWorkspaceID string) context.Context {
	return context.WithValue(ctx, selectedWorkspaceKey{}, strings.TrimSpace(externalWorkspaceID))
}

func SelectedWorkspace(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(selectedWorkspaceKey{}).(string)
	return value, ok && value != ""
}
