// Package demoserver provides the OIDC protected example endpoint, so the CLI
// can be tried out end to end without a separate backend. It validates the
// bearer token against the JWKS of the issuer.
package demoserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Options configure the example resource server.
type Options struct {
	// Addr is the listen address, for example ":8080".
	Addr string
	// Issuer is the OIDC issuer whose tokens are accepted.
	Issuer string
	// Audience is the expected "aud" claim. When empty the audience check is
	// skipped, which is convenient for providers that put the client ID there.
	Audience string
}

// Run serves the example endpoint until ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return fmt.Errorf("OIDC discovery for %s: %w", opts.Issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID:          opts.Audience,
		SkipClientIDCheck: opts.Audience == "",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.Handle("/api/hello", authenticate(verifier, http.HandlerFunc(hello)))

	server := &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	host := opts.Addr
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	fmt.Printf("example endpoint listening on http://%s/api/hello\n", host)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// claimsKey is the context key under which the verified claims are stored.
type claimsKey struct{}

// authenticate rejects requests without a valid bearer token.
func authenticate(verifier *oidc.IDTokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		raw, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			unauthorized(w, "invalid_request", "a bearer token is required")
			return
		}
		token, err := verifier.Verify(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			unauthorized(w, "invalid_token", err.Error())
			return
		}
		var claims map[string]any
		if err := token.Claims(&claims); err != nil {
			unauthorized(w, "invalid_token", "claims cannot be parsed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

func hello(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(claimsKey{}).(map[string]any)
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "hello from the OIDC protected endpoint",
		"subject": claims["sub"],
		"claims":  claims,
	})
}

// unauthorized answers with the WWW-Authenticate header required by RFC 6750,
// which is what makes the CLI retry with a fresh login.
func unauthorized(w http.ResponseWriter, code, description string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=%q, error_description=%q", code, description))
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             code,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}
