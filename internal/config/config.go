// Package config resolves CLI configuration from flags, environment variables
// and built-in defaults, in that order of precedence.
package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// AppName is used for the default configuration directory name.
	AppName = "oidc-cli"
	// EnvPrefix is prepended to every environment variable this CLI reads.
	EnvPrefix = "OIDCCLI_"
)

// Config holds every setting the CLI needs to talk to the identity provider
// and to the protected API.
type Config struct {
	// Issuer is the OIDC issuer URL, e.g. https://example.eu.auth0.com/.
	// Discovery happens at <issuer>/.well-known/openid-configuration.
	Issuer string
	// ClientID of the application registered at the identity provider.
	ClientID string
	// ClientSecret is optional. A CLI is a public client and should normally
	// use PKCE without a secret, but some providers insist on a secret even
	// for the authorization code flow.
	ClientSecret string
	// ScopeList is a space or comma separated list of scopes.
	ScopeList string
	// Audience is sent as an extra authorization parameter. Auth0 and some
	// other providers need it to issue a JWT access token for an API.
	Audience string
	// RedirectPort is the fixed port for the loopback redirect URI. Zero picks
	// a random free port, which only works if the provider allows any port on
	// http://127.0.0.1 (as recommended by RFC 8252).
	RedirectPort int
	// APIURL is the protected endpoint the CLI calls by default.
	APIURL string
	// TokenFile is where the access token is cached.
	TokenFile string
	// NoBrowser disables the interactive login, failing instead.
	NoBrowser bool
}

// Default returns the configuration with environment variables applied.
func Default() Config {
	return Config{
		Issuer:       env("ISSUER", ""),
		ClientID:     env("CLIENT_ID", ""),
		ClientSecret: env("CLIENT_SECRET", ""),
		ScopeList:    env("SCOPES", "openid profile email offline_access"),
		Audience:     env("AUDIENCE", ""),
		RedirectPort: envInt("REDIRECT_PORT", 0),
		APIURL:       env("API_URL", ""),
		TokenFile:    env("TOKEN_FILE", DefaultTokenFile()),
	}
}

// RegisterFlags adds the common flags to fs, using c as the defaults.
func (c *Config) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Issuer, "issuer", c.Issuer, "OIDC issuer URL ($OIDCCLI_ISSUER)")
	fs.StringVar(&c.ClientID, "client-id", c.ClientID, "OAuth2 client ID ($OIDCCLI_CLIENT_ID)")
	fs.StringVar(&c.ClientSecret, "client-secret", c.ClientSecret, "OAuth2 client secret, only if the provider requires one ($OIDCCLI_CLIENT_SECRET)")
	fs.StringVar(&c.ScopeList, "scopes", c.ScopeList, "requested scopes, space or comma separated ($OIDCCLI_SCOPES)")
	fs.StringVar(&c.Audience, "audience", c.Audience, "audience parameter for the API ($OIDCCLI_AUDIENCE)")
	fs.IntVar(&c.RedirectPort, "redirect-port", c.RedirectPort, "fixed loopback port for the redirect URI, 0 for a random one ($OIDCCLI_REDIRECT_PORT)")
	fs.StringVar(&c.TokenFile, "token-file", c.TokenFile, "path of the cached token ($OIDCCLI_TOKEN_FILE)")
	fs.BoolVar(&c.NoBrowser, "no-browser", c.NoBrowser, "never open a browser, fail if no usable token is cached")
}

// RegisterAPIFlag adds the flag for the protected endpoint.
func (c *Config) RegisterAPIFlag(fs *flag.FlagSet) {
	fs.StringVar(&c.APIURL, "url", c.APIURL, "URL of the protected endpoint ($OIDCCLI_API_URL)")
}

// Scopes splits ScopeList into individual scopes.
func (c Config) Scopes() []string {
	fields := strings.FieldsFunc(c.ScopeList, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n'
	})
	return fields
}

// Validate reports whether the settings needed for authentication are present.
func (c Config) Validate() error {
	var missing []string
	if c.Issuer == "" {
		missing = append(missing, "--issuer")
	}
	if c.ClientID == "" {
		missing = append(missing, "--client-id")
	}
	if len(missing) > 0 {
		return errors.New("missing required configuration: " + strings.Join(missing, ", "))
	}
	return nil
}

// DefaultTokenFile is $XDG_CONFIG_HOME/oidc-cli/token.json, falling back to
// ~/.config/oidc-cli/token.json.
func DefaultTokenFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", "."+AppName, "token.json")
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, AppName, "token.json")
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
