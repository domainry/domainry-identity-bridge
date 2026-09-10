package module

import (
	"context"
	"fmt"
	"os"

	"github.com/domainry/domainry-identity-bridge/config"
	"github.com/domainry/domainry-identity-bridge/internal/assembly"
	identity "github.com/domainry/domainry-identity-sdk"
)

type Factory struct {
	configFile string
	options    Options
}

// NewFactory is selected by generated project composition. The configuration
// path is explicit and all provider-specific values remain outside generated Go.
func NewFactory(configFile string, options Options) *Factory {
	return &Factory{configFile: configFile, options: options}
}

func (*Factory) Open(context.Context, identity.ApplicationRef) (identity.Binding, error) {
	return nil, fmt.Errorf("external identity requires the Runtime database and Workspace host")
}

func (factory *Factory) OpenExternalWithDatabase(ctx context.Context, application identity.ApplicationRef, handle identity.DatabaseHandle) (identity.Binding, error) {
	if factory.configFile == "" {
		return nil, fmt.Errorf("external identity configuration path is required")
	}
	file, err := os.Open(factory.configFile)
	if err != nil {
		return nil, fmt.Errorf("open external identity configuration: %w", err)
	}
	defer file.Close()
	cfg, err := config.Load(file)
	if err != nil {
		return nil, err
	}
	return assembly.Open(ctx, cfg, application, handle, factory.options.Transport, factory.options.LookupEnvironment, factory.options.Now)
}

var _ identity.ExternalDatabaseFactory = (*Factory)(nil)

// ConfigPathFromEnvironment selects a configuration document, never a provider
// implementation. Relative paths resolve from the generated project root.
func ConfigPathFromEnvironment() string {
	if path := os.Getenv("DOMAINRY_IDENTITY_BRIDGE_CONFIG_FILE"); path != "" {
		return path
	}
	return "config/identity-external.json"
}
