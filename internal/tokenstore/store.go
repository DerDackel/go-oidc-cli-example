// Package tokenstore persists the OAuth2 token of the current user in a single
// JSON file, comparable to ~/.aws/sso/cache used by the AWS CLI.
package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

// expiryLeeway treats tokens that are about to expire as already expired, so a
// request cannot fail because of the round trip time.
const expiryLeeway = 30 * time.Second

// Token is the on-disk representation of a token plus the identity of the
// provider it was issued by.
type Token struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	TokenType    string    `json:"token_type,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

// Expired reports whether the access token is unusable, taking the leeway into
// account. A token without an expiry is assumed to stay valid.
func (t *Token) Expired() bool {
	if t == nil || t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return time.Now().Add(expiryLeeway).After(t.Expiry)
}

// MatchesProvider reports whether the token was issued for the given issuer and
// client. A cached token from a different provider must not be reused.
func (t *Token) MatchesProvider(issuer, clientID string) bool {
	return t != nil && t.Issuer == issuer && t.ClientID == clientID
}

// OAuth2 converts the stored token back into an oauth2.Token.
func (t *Token) OAuth2() *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  t.AccessToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}
	if t.IDToken != "" {
		tok = tok.WithExtra(map[string]any{"id_token": t.IDToken})
	}
	return tok
}

// FromOAuth2 builds a storable token. The refresh token and the ID token of a
// previous token are kept when the provider did not return new ones, which is
// the usual behaviour for refresh responses.
func FromOAuth2(tok *oauth2.Token, issuer, clientID string, previous *Token) *Token {
	stored := &Token{
		Issuer:      issuer,
		ClientID:    clientID,
		TokenType:   tok.TokenType,
		AccessToken: tok.AccessToken,
		Expiry:      tok.Expiry,
		ObtainedAt:  time.Now(),
	}
	stored.RefreshToken = tok.RefreshToken
	if idToken, ok := tok.Extra("id_token").(string); ok {
		stored.IDToken = idToken
	}
	if scope, ok := tok.Extra("scope").(string); ok {
		stored.Scope = scope
	}
	if previous != nil {
		if stored.RefreshToken == "" {
			stored.RefreshToken = previous.RefreshToken
		}
		if stored.IDToken == "" {
			stored.IDToken = previous.IDToken
		}
		if stored.Scope == "" {
			stored.Scope = previous.Scope
		}
	}
	return stored
}

// Store reads and writes the token file.
type Store struct {
	path string
}

// New returns a store backed by the file at path.
func New(path string) *Store {
	return &Store{path: path}
}

// Path is the location of the token file.
func (s *Store) Path() string { return s.path }

// Load returns the cached token. It returns a nil token and no error when the
// file does not exist yet.
func (s *Store) Load() (*Token, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read token file %s: %w", s.path, err)
	}
	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		// A corrupt cache must not block the CLI; a new login replaces it.
		return nil, fmt.Errorf("parse token file %s: %w", s.path, err)
	}
	return &tok, nil
}

// Save writes the token atomically with owner-only permissions.
func (s *Store) Save(tok *Token) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token directory %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".token-*.json")
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary token file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace token file %s: %w", s.path, err)
	}
	return nil
}

// Delete removes the cached token. Deleting a missing file is not an error.
func (s *Store) Delete() error {
	err := os.Remove(s.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove token file %s: %w", s.path, err)
	}
	return nil
}
