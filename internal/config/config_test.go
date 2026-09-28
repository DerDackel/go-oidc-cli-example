package config

import (
	"flag"
	"slices"
	"testing"
)

func TestScopesSplitting(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"openid profile", []string{"openid", "profile"}},
		{"openid,profile,email", []string{"openid", "profile", "email"}},
		{"  openid   offline_access ", []string{"openid", "offline_access"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := Config{ScopeList: tt.in}.Scopes()
		if !slices.Equal(got, tt.want) {
			t.Errorf("Scopes(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{Issuer: "https://issuer.example", ClientID: "cli"}).Validate(); err != nil {
		t.Errorf("complete configuration rejected: %v", err)
	}
	if err := (Config{ClientID: "cli"}).Validate(); err == nil {
		t.Error("missing issuer accepted")
	}
	if err := (Config{Issuer: "https://issuer.example"}).Validate(); err == nil {
		t.Error("missing client ID accepted")
	}
}

func TestEnvironmentIsTheDefaultAndFlagsWin(t *testing.T) {
	t.Setenv(EnvPrefix+"ISSUER", "https://from-env.example")
	t.Setenv(EnvPrefix+"CLIENT_ID", "env-client")
	t.Setenv(EnvPrefix+"REDIRECT_PORT", "8400")

	cfg := Default()
	if cfg.Issuer != "https://from-env.example" || cfg.ClientID != "env-client" {
		t.Fatalf("environment not applied: %+v", cfg)
	}
	if cfg.RedirectPort != 8400 {
		t.Errorf("redirect port: got %d, want 8400", cfg.RedirectPort)
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg.RegisterFlags(fs)
	if err := fs.Parse([]string{"-issuer", "https://from-flag.example"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Issuer != "https://from-flag.example" {
		t.Errorf("issuer: got %q, want the flag value", cfg.Issuer)
	}
	if cfg.ClientID != "env-client" {
		t.Errorf("client ID: got %q, want the environment value to survive", cfg.ClientID)
	}
}
