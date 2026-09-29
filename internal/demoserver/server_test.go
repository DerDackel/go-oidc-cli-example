package demoserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// issuerStub serves just enough OIDC metadata to verify a bearer token.
type issuerStub struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newIssuerStub(t *testing.T) *issuerStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stub := &issuerStub{key: key}

	mux := http.NewServeMux()
	stub.server = httptest.NewServer(mux)
	t.Cleanup(stub.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                stub.server.URL,
			"authorization_endpoint":                stub.server.URL + "/auth",
			"token_endpoint":                        stub.server.URL + "/token",
			"jwks_uri":                              stub.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     "test-key",
			Algorithm: "RS256",
			Use:       "sig",
		}}})
	})
	return stub
}

// accessToken signs a JWT access token for the given audience.
func (s *issuerStub) accessToken(t *testing.T, audience string, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: "test-key"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": s.server.URL,
		"sub": "user-42",
		"aud": audience,
		"exp": expiry.Unix(),
		"iat": time.Now().Unix(),
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

// protectedHandler builds the same handler chain Run installs.
func protectedHandler(t *testing.T, stub *issuerStub, audience string) http.Handler {
	t.Helper()
	provider, err := oidc.NewProvider(context.Background(), stub.server.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience, SkipClientIDCheck: audience == ""})
	return authenticate(verifier, http.HandlerFunc(hello))
}

func TestEndpointAcceptsValidToken(t *testing.T) {
	stub := newIssuerStub(t)
	handler := protectedHandler(t, stub, "api")

	req := httptest.NewRequest(http.MethodGet, "/api/hello", nil)
	req.Header.Set("Authorization", "Bearer "+stub.accessToken(t, "api", time.Now().Add(time.Hour)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body %s", rec.Code, rec.Body)
	}
	var payload struct {
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Subject != "user-42" {
		t.Errorf("subject: got %q, want %q", payload.Subject, "user-42")
	}
}

func TestEndpointRejectsBadTokens(t *testing.T) {
	stub := newIssuerStub(t)
	other := newIssuerStub(t)
	handler := protectedHandler(t, stub, "api")

	tests := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"not a bearer token", "Basic dXNlcjpwYXNz"},
		{"garbage token", "Bearer not-a-jwt"},
		{"expired token", "Bearer " + stub.accessToken(t, "api", time.Now().Add(-time.Minute))},
		{"wrong audience", "Bearer " + stub.accessToken(t, "someone-else", time.Now().Add(time.Hour))},
		{"foreign signature", "Bearer " + other.accessToken(t, "api", time.Now().Add(time.Hour))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/hello", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("a 401 must carry a WWW-Authenticate header")
			}
		})
	}
}
