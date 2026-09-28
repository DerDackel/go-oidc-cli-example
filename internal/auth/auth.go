// Package auth obtains OIDC access tokens for the CLI: it reuses a cached
// token, refreshes it silently when possible and otherwise runs the browser
// based authorization code flow with PKCE (RFC 7636) and a loopback redirect
// URI (RFC 8252).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/DerDackel/go-oidc-cli-example/internal/config"
	"github.com/DerDackel/go-oidc-cli-example/internal/tokenstore"
)

// loginTimeout bounds how long the CLI waits for the user to finish the login
// in the browser.
const loginTimeout = 5 * time.Minute

// ErrLoginRequired is returned when a valid token is needed but the CLI is not
// allowed to open a browser.
var ErrLoginRequired = errors.New("no valid token cached, run `oidc-cli login` or drop --no-browser")

// Authenticator turns configuration into usable access tokens.
type Authenticator struct {
	cfg      config.Config
	provider *oidc.Provider
	store    *tokenstore.Store
	// Out receives progress messages such as the authorization URL.
	Out *os.File
}

// New discovers the provider metadata at the configured issuer.
func New(ctx context.Context, cfg config.Config) (*Authenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", cfg.Issuer, err)
	}
	return &Authenticator{
		cfg:      cfg,
		provider: provider,
		store:    tokenstore.New(cfg.TokenFile),
		Out:      os.Stderr,
	}, nil
}

// Store exposes the token cache, for the logout and token commands.
func (a *Authenticator) Store() *tokenstore.Store { return a.store }

// Token returns a usable access token. It reuses the cached one, refreshes it
// when it is expired and a refresh token is available, and falls back to the
// interactive browser login.
func (a *Authenticator) Token(ctx context.Context) (*tokenstore.Token, error) {
	cached, err := a.store.Load()
	if err != nil {
		// A cache that cannot be read is reported but never fatal: a fresh
		// login recreates it.
		fmt.Fprintf(a.Out, "warning: %v\n", err)
		cached = nil
	}
	if !cached.MatchesProvider(a.cfg.Issuer, a.cfg.ClientID) {
		cached = nil
	}
	if cached != nil && !cached.Expired() {
		return cached, nil
	}
	if cached != nil && cached.RefreshToken != "" {
		refreshed, err := a.refresh(ctx, cached)
		if err == nil {
			return refreshed, nil
		}
		fmt.Fprintf(a.Out, "refresh failed (%v), starting a new login\n", err)
	}
	if a.cfg.NoBrowser {
		return nil, ErrLoginRequired
	}
	return a.Login(ctx)
}

// refresh exchanges the refresh token for a new access token.
func (a *Authenticator) refresh(ctx context.Context, cached *tokenstore.Token) (*tokenstore.Token, error) {
	oauthCfg := a.oauthConfig("")
	// An empty access token with an expiry in the past forces the token source
	// to perform the refresh immediately.
	source := oauthCfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: cached.RefreshToken,
		Expiry:       time.Now().Add(-time.Minute),
	})
	tok, err := source.Token()
	if err != nil {
		return nil, err
	}
	stored := tokenstore.FromOAuth2(tok, a.cfg.Issuer, a.cfg.ClientID, cached)
	if err := a.store.Save(stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// Login always runs the interactive browser flow and replaces the cached token.
func (a *Authenticator) Login(ctx context.Context) (*tokenstore.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.cfg.RedirectPort)))
	if err != nil {
		return nil, fmt.Errorf("listen for the OAuth2 redirect: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	oauthCfg := a.oauthConfig(redirectURI)

	state, err := randomString()
	if err != nil {
		return nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline, // ask for a refresh token where that is opt-in
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	}
	if a.cfg.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", a.cfg.Audience))
	}
	authURL := oauthCfg.AuthCodeURL(state, opts...)

	results := make(chan callbackResult, 1)
	server := &http.Server{Handler: callbackHandler(state, results)}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(a.Out, "Opening the browser for login at:\n%s\n", authURL)
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(a.Out, "could not open a browser automatically (%v), open the URL above manually\n", err)
	}

	var result callbackResult
	select {
	case result = <-results:
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the login to finish: %w", ctx.Err())
	}
	if result.err != nil {
		return nil, result.err
	}

	tok, err := oauthCfg.Exchange(ctx, result.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if err := a.verifyIDToken(ctx, tok, nonce); err != nil {
		return nil, err
	}

	stored := tokenstore.FromOAuth2(tok, a.cfg.Issuer, a.cfg.ClientID, nil)
	if err := a.store.Save(stored); err != nil {
		return nil, err
	}
	fmt.Fprintf(a.Out, "Login successful, token stored in %s\n", a.store.Path())
	return stored, nil
}

// Logout deletes the cached token and, when the provider advertises an end
// session endpoint, returns the URL that also ends the browser session.
func (a *Authenticator) Logout() (endSessionURL string, err error) {
	cached, _ := a.store.Load()
	if err := a.store.Delete(); err != nil {
		return "", err
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := a.provider.Claims(&metadata); err != nil || metadata.EndSessionEndpoint == "" {
		return "", nil
	}
	u, err := url.Parse(metadata.EndSessionEndpoint)
	if err != nil {
		return "", nil
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	if cached != nil && cached.IDToken != "" {
		q.Set("id_token_hint", cached.IDToken)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// verifyIDToken checks the signature, audience and nonce of the ID token when
// the provider returned one. Providers that only issue an access token, for
// example because "openid" was not requested, are accepted as they are.
func (a *Authenticator) verifyIDToken(ctx context.Context, tok *oauth2.Token, nonce string) error {
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil
	}
	verifier := a.provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return fmt.Errorf("verify ID token: %w", err)
	}
	if idToken.Nonce != nonce {
		return errors.New("verify ID token: nonce mismatch")
	}
	return nil
}

// oauthConfig builds the OAuth2 client configuration. redirectURI is empty for
// requests that do not need one, such as a refresh.
func (a *Authenticator) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       a.cfg.Scopes(),
	}
}

// randomString returns 32 bytes of entropy, URL-safe encoded, for the state and
// the nonce.
func randomString() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
