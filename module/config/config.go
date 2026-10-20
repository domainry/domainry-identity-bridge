// Package config exposes the external Identity module's configuration contract.
// Validation and loading remain owned by the private implementation.
package config

import (
	"io"

	internalconfig "github.com/domainry/domainry-identity-bridge/internal/config"
)

const Version = internalconfig.Version

type Browser = internalconfig.Browser
type Config = internalconfig.Config
type Provider = internalconfig.Provider
type Verification = internalconfig.Verification
type Credential = internalconfig.Credential
type SecretReference = internalconfig.SecretReference
type Response = internalconfig.Response
type ResponseCheck = internalconfig.ResponseCheck
type PersonalWorkspace = internalconfig.PersonalWorkspace
type ServiceSubject = internalconfig.ServiceSubject
type WorkspaceNameFields = internalconfig.WorkspaceNameFields

func Load(reader io.Reader) (Config, error) { return internalconfig.Load(reader) }
