package provider

import (
	"net/http"

	"github.com/domainry/domainry-identity-bridge/internal/config"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
)

func applyCredential(request *http.Request, credential config.Credential, value string) error {
	placements := append([]config.CredentialPlacement{{
		Location: credential.Location,
		Name:     credential.Name,
		Prefix:   credential.Prefix,
	}}, credential.Mirrors...)
	for _, placement := range placements {
		switch placement.Location {
		case "header":
			request.Header.Set(placement.Name, placement.Prefix+value)
		case "cookie":
			cookie := &http.Cookie{Name: placement.Name, Value: value}
			if err := cookie.Valid(); err != nil {
				return bridge.ErrCredentialRejected
			}
			request.AddCookie(cookie)
		case "json":
			// The primary JSON placement was already written to the request body.
		}
	}
	return nil
}
