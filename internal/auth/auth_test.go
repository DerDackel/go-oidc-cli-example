package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/DerDackel/go-oidc-cli-example/internal/config"
	"github.com/DerDackel/go-oidc-cli-example/internal/tokenstore"
)

// fakeProvider is a minimal OIDC provider: discovery, JWKS, an authorization
// endpoint that redirects straight back and a token endpoint that enforces
// PKCE.
type fakeProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	// captured from the authorization request
	challenge string
	nonce     string
	// verifier sent to the token endpoint
	sentVerifier string
	refreshCalls int
}

func newFakeProvider(t *testing.T, clientID string) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeProvider{key: key}

	mux := http.NewServeMux()
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/jwks",
			"end_session_endpoint":                  p.server.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     "test-key",
			Algorithm: "RS256",
			Use:       "sig",
		}}})
	})

	// The authorization endpoint stands in for the user approving the login in
	// the browser: it redirects to the loopback URI with a code.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.challenge = q.Get("code_challenge")
		p.nonce = q.Get("nonce")
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE S256 expected", http.StatusBadRequest)
			return
		}
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		rq := redirect.Query()
		rq.Set("code", "the-code")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			p.sentVerifier = r.Form.Get("code_verifier")
			if challengeOf(p.sentVerifier) != p.challenge {
				http.Error(w, "PKCE verification failed", http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{
				"access_token":  "access-1",
				"refresh_token": "refresh-1",
				"id_token":      p.idToken(t, clientID, p.nonce),
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "openid offline_access",
			})
		case "refresh_token":
			p.refreshCalls++
			if r.Form.Get("refresh_token") != "refresh-1" {
				http.Error(w, "unknown refresh token", http.StatusBadRequest)
				return
			}
			// Like most providers, no new refresh token is returned here.
			writeJSON(w, map[string]any{
				"access_token": "access-2",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.Error(w, "unsupported grant", http.StatusBadRequest)
		}
	})

	return p
}

func (p *fakeProvider) idToken(t *testing.T, audience, nonce string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: "test-key"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss":   p.server.URL,
		"sub":   "user-42",
		"aud":   audience,
		"nonce": nonce,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "user@example.com",
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	serialized, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return serialized
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// stubBrowser replaces the browser with an HTTP client that follows the
// authorization URL, which ends in the loopback callback of the CLI.
func stubBrowser(t *testing.T) {
	t.Helper()
	previous := openBrowser
	openBrowser = func(rawURL string) error {
		go func() {
			resp, err := http.Get(rawURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = previous })
}

func testConfig(t *testing.T, provider *fakeProvider) config.Config {
	t.Helper()
	return config.Config{
		Issuer:    provider.server.URL,
		ClientID:  "test-client",
		ScopeList: "openid offline_access",
		TokenFile: filepath.Join(t.TempDir(), "token.json"),
	}
}

func TestLoginStoresVerifiedToken(t *testing.T) {
	provider := newFakeProvider(t, "test-client")
	stubBrowser(t)
	cfg := testConfig(t, provider)

	authenticator, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authenticator.Out = devNull(t)

	tok, err := authenticator.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken != "access-1" {
		t.Errorf("access token: got %q, want %q", tok.AccessToken, "access-1")
	}
	if tok.RefreshToken != "refresh-1" {
		t.Errorf("refresh token: got %q, want %q", tok.RefreshToken, "refresh-1")
	}
	if provider.sentVerifier == "" || challengeOf(provider.sentVerifier) != provider.challenge {
		t.Error("the code verifier was not sent or does not match the challenge")
	}

	// The token must have reached the cache on disk as well.
	cached, err := tokenstore.New(cfg.TokenFile).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cached == nil || cached.AccessToken != "access-1" {
		t.Errorf("cached token: got %+v, want the fresh access token", cached)
	}
}

func TestTokenReusesCachedToken(t *testing.T) {
	provider := newFakeProvider(t, "test-client")
	cfg := testConfig(t, provider)
	// Any browser use here would be a bug.
	previous := openBrowser
	openBrowser = func(string) error {
		t.Error("a valid cached token must not trigger a browser login")
		return nil
	}
	t.Cleanup(func() { openBrowser = previous })

	store := tokenstore.New(cfg.TokenFile)
	if err := store.Save(&tokenstore.Token{
		Issuer:      cfg.Issuer,
		ClientID:    cfg.ClientID,
		AccessToken: "cached-access",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	authenticator, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authenticator.Out = devNull(t)

	tok, err := authenticator.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "cached-access" {
		t.Errorf("access token: got %q, want the cached one", tok.AccessToken)
	}
}

func TestTokenRefreshesExpiredTokenWithoutBrowser(t *testing.T) {
	provider := newFakeProvider(t, "test-client")
	cfg := testConfig(t, provider)
	previous := openBrowser
	openBrowser = func(string) error {
		t.Error("an expired token with a refresh token must be refreshed silently")
		return nil
	}
	t.Cleanup(func() { openBrowser = previous })

	store := tokenstore.New(cfg.TokenFile)
	if err := store.Save(&tokenstore.Token{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		AccessToken:  "expired-access",
		RefreshToken: "refresh-1",
		IDToken:      "kept-id-token",
		Expiry:       time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	authenticator, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authenticator.Out = devNull(t)

	tok, err := authenticator.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "access-2" {
		t.Errorf("access token: got %q, want the refreshed one", tok.AccessToken)
	}
	if provider.refreshCalls != 1 {
		t.Errorf("refresh calls: got %d, want 1", provider.refreshCalls)
	}
	// The provider returned neither a refresh token nor an ID token, both must
	// survive in the cache.
	cached, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cached.RefreshToken != "refresh-1" {
		t.Errorf("refresh token: got %q, want it kept", cached.RefreshToken)
	}
	if cached.IDToken != "kept-id-token" {
		t.Errorf("ID token: got %q, want it kept", cached.IDToken)
	}
}

func TestTokenOfAnotherProviderIsIgnored(t *testing.T) {
	provider := newFakeProvider(t, "test-client")
	stubBrowser(t)
	cfg := testConfig(t, provider)

	store := tokenstore.New(cfg.TokenFile)
	if err := store.Save(&tokenstore.Token{
		Issuer:      "https://someone-else.example",
		ClientID:    cfg.ClientID,
		AccessToken: "foreign-access",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	authenticator, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authenticator.Out = devNull(t)

	tok, err := authenticator.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "access-1" {
		t.Errorf("access token: got %q, want a freshly obtained one", tok.AccessToken)
	}
}

func TestNoBrowserFailsWithoutUsableToken(t *testing.T) {
	provider := newFakeProvider(t, "test-client")
	cfg := testConfig(t, provider)
	cfg.NoBrowser = true

	authenticator, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authenticator.Out = devNull(t)

	if _, err := authenticator.Token(context.Background()); err == nil {
		t.Fatal("--no-browser without a cached token must fail")
	}
}

// devNull swallows the progress output of the authenticator.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
