package config

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Browser configures the existing login authority's browser handoff. No
// credentials or server-only verifier settings are disclosed to the browser.
type Browser struct {
	DisplayName    string     `json:"display_name"`
	LoginURL       string     `json:"login_url"`
	LogoutURL      string     `json:"logout_url,omitempty"`
	Credential     Credential `json:"credential"`
	AllowedOrigins []string   `json:"allowed_origins"`
}

func (b Browser) Validate() error {
	if strings.TrimSpace(b.DisplayName) == "" {
		return fmt.Errorf("browser.display_name is required")
	}
	urls := []string{b.LoginURL}
	if b.LogoutURL != "" {
		urls = append(urls, b.LogoutURL)
	}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("browser login/logout URLs must be absolute HTTPS URLs")
		}
	}
	c := b.Credential
	if c.Location != "header" && c.Location != "cookie" {
		return fmt.Errorf("browser credential location must be header or cookie")
	}
	if !headerKey.MatchString(c.Name) || strings.ContainsAny(c.Prefix, "\r\n") {
		return fmt.Errorf("invalid browser credential name or prefix")
	}
	if c.Location == "header" && !allowedHeader(c.Name) {
		return fmt.Errorf("reserved browser credential header")
	}
	if c.Location == "cookie" && c.Prefix != "" {
		return fmt.Errorf("cookie credential cannot have a prefix")
	}
	if len(b.AllowedOrigins) == 0 {
		return fmt.Errorf("browser.allowed_origins is required")
	}
	seen := map[string]bool{}
	for _, origin := range b.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || seen[origin] {
			return fmt.Errorf("browser origins must be unique HTTPS origins")
		}
		seen[origin] = true
	}
	// Exercise the standard cookie parser at validation time as well.
	if c.Location == "cookie" {
		if err := (&http.Cookie{Name: c.Name, Value: "validation"}).Valid(); err != nil {
			return fmt.Errorf("invalid browser cookie name")
		}
	}
	return nil
}
