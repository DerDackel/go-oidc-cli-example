package tokenstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "token.json")
	store := New(path)

	want := &Token{
		Issuer:       "https://issuer.example",
		ClientID:     "cli",
		TokenType:    "Bearer",
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour).Round(time.Second),
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Errorf("tokens differ: got %+v, want %+v", got, want)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Errorf("expiry: got %v, want %v", got.Expiry, want.Expiry)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions: got %o, want 600", perm)
	}
}

func TestLoadMissingFile(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "token.json"))
	tok, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tok != nil {
		t.Errorf("got %+v, want nil for a missing file", tok)
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "token.json"))
	if err := store.Delete(); err != nil {
		t.Errorf("Delete on a missing file: %v", err)
	}
}

func TestExpired(t *testing.T) {
	tests := []struct {
		name string
		tok  *Token
		want bool
	}{
		{"nil", nil, true},
		{"no access token", &Token{}, true},
		{"no expiry", &Token{AccessToken: "a"}, false},
		{"valid", &Token{AccessToken: "a", Expiry: time.Now().Add(time.Hour)}, false},
		{"expired", &Token{AccessToken: "a", Expiry: time.Now().Add(-time.Minute)}, true},
		{"within leeway", &Token{AccessToken: "a", Expiry: time.Now().Add(5 * time.Second)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.Expired(); got != tt.want {
				t.Errorf("Expired() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMatchesProvider(t *testing.T) {
	tok := &Token{Issuer: "https://issuer.example", ClientID: "cli"}
	if !tok.MatchesProvider("https://issuer.example", "cli") {
		t.Error("token of the same provider must match")
	}
	if tok.MatchesProvider("https://other.example", "cli") {
		t.Error("token of another issuer must not match")
	}
	if (*Token)(nil).MatchesProvider("https://issuer.example", "cli") {
		t.Error("nil token must not match")
	}
}

func TestFromOAuth2KeepsPreviousRefreshToken(t *testing.T) {
	previous := &Token{RefreshToken: "old-refresh", IDToken: "old-id", Scope: "openid"}
	// A refresh response commonly omits the refresh token and the ID token.
	refreshed := &oauth2.Token{AccessToken: "new-access", TokenType: "Bearer"}

	got := FromOAuth2(refreshed, "https://issuer.example", "cli", previous)

	if got.RefreshToken != "old-refresh" {
		t.Errorf("refresh token: got %q, want the previous one", got.RefreshToken)
	}
	if got.IDToken != "old-id" {
		t.Errorf("ID token: got %q, want the previous one", got.IDToken)
	}
	if got.Scope != "openid" {
		t.Errorf("scope: got %q, want the previous one", got.Scope)
	}
	if got.Issuer != "https://issuer.example" || got.ClientID != "cli" {
		t.Errorf("provider identity not stored: %+v", got)
	}
}

func TestFromOAuth2PrefersNewValues(t *testing.T) {
	previous := &Token{RefreshToken: "old-refresh"}
	fresh := (&oauth2.Token{AccessToken: "a", RefreshToken: "new-refresh"}).
		WithExtra(map[string]any{"id_token": "new-id"})

	got := FromOAuth2(fresh, "https://issuer.example", "cli", previous)

	if got.RefreshToken != "new-refresh" {
		t.Errorf("refresh token: got %q, want the new one", got.RefreshToken)
	}
	if got.IDToken != "new-id" {
		t.Errorf("ID token: got %q, want the new one", got.IDToken)
	}
}
