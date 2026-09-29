// Command oidc-cli calls an OIDC protected HTTP endpoint. It caches the access
// token in a file and, when that token is missing or expired and cannot be
// refreshed, opens a browser based login flow, much like the AWS CLI does for
// IAM Identity Center.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DerDackel/go-oidc-cli-example/internal/api"
	"github.com/DerDackel/go-oidc-cli-example/internal/auth"
	"github.com/DerDackel/go-oidc-cli-example/internal/config"
	"github.com/DerDackel/go-oidc-cli-example/internal/demoserver"
	"github.com/DerDackel/go-oidc-cli-example/internal/tokenstore"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no command given")
	}
	command, args := args[0], args[1:]
	switch command {
	case "login":
		return cmdLogin(ctx, args)
	case "logout":
		return cmdLogout(ctx, args)
	case "token":
		return cmdToken(ctx, args)
	case "status":
		return cmdStatus(args)
	case "call":
		return cmdCall(ctx, args)
	case "serve":
		return cmdServe(ctx, args)
	case "version", "-v", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

// cmdLogin always runs the browser flow, even if a valid token is cached.
func cmdLogin(ctx context.Context, args []string) error {
	cfg, err := parse("login", args, false)
	if err != nil {
		return err
	}
	authenticator, err := auth.New(ctx, cfg)
	if err != nil {
		return err
	}
	tok, err := authenticator.Login(ctx)
	if err != nil {
		return err
	}
	printTokenSummary(os.Stdout, tok)
	return nil
}

// cmdLogout removes the cached token.
func cmdLogout(ctx context.Context, args []string) error {
	cfg, err := parse("logout", args, false)
	if err != nil {
		return err
	}
	authenticator, err := auth.New(ctx, cfg)
	if err != nil {
		// Without a reachable provider the local token can still be dropped.
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		return tokenstore.New(cfg.TokenFile).Delete()
	}
	endSessionURL, err := authenticator.Logout()
	if err != nil {
		return err
	}
	fmt.Printf("Cached token removed from %s\n", cfg.TokenFile)
	if endSessionURL != "" {
		fmt.Printf("To end the browser session as well, open:\n%s\n", endSessionURL)
	}
	return nil
}

// cmdToken prints a usable access token, logging in if needed, so it can be
// embedded in other commands:
//
//	curl -H "Authorization: Bearer $(oidc-cli token)" https://api.example.com/
func cmdToken(ctx context.Context, args []string) error {
	cfg, err := parse("token", args, false)
	if err != nil {
		return err
	}
	authenticator, err := auth.New(ctx, cfg)
	if err != nil {
		return err
	}
	tok, err := authenticator.Token(ctx)
	if err != nil {
		return err
	}
	fmt.Println(tok.AccessToken)
	return nil
}

// cmdStatus reports on the cached token without contacting the provider.
func cmdStatus(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfg.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	tok, err := tokenstore.New(cfg.TokenFile).Load()
	if err != nil {
		return err
	}
	if tok == nil {
		fmt.Printf("No token cached in %s\n", cfg.TokenFile)
		return nil
	}
	fmt.Printf("Token file:    %s\n", cfg.TokenFile)
	printTokenSummary(os.Stdout, tok)
	return nil
}

// cmdCall performs the authenticated GET request against the example endpoint.
func cmdCall(ctx context.Context, args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	cfg.RegisterFlags(fs)
	cfg.RegisterAPIFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// A positional argument overrides --url, so `oidc-cli call <url>` works.
	if fs.NArg() > 0 {
		cfg.APIURL = fs.Arg(0)
	}
	if cfg.APIURL == "" {
		return errors.New("no endpoint given, pass a URL or set --url / $OIDCCLI_API_URL")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	authenticator, err := auth.New(ctx, cfg)
	if err != nil {
		return err
	}
	resp, err := api.New(authenticator).Get(ctx, cfg.APIURL)
	if err != nil {
		return err
	}
	os.Stdout.Write(resp.Body)
	if len(resp.Body) > 0 && !strings.HasSuffix(string(resp.Body), "\n") {
		fmt.Println()
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// cmdServe runs the example resource server, so the CLI can be tried out
// against a local endpoint.
func cmdServe(ctx context.Context, args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address of the example endpoint")
	cfg.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.Issuer == "" {
		return errors.New("missing required configuration: --issuer")
	}
	audience := cfg.Audience
	if audience == "" {
		// Many providers issue access tokens whose audience is the client ID.
		audience = cfg.ClientID
	}
	return demoserver.Run(ctx, demoserver.Options{
		Addr:     *addr,
		Issuer:   cfg.Issuer,
		Audience: audience,
	})
}

// parse builds the configuration for a command that needs authentication.
func parse(name string, args []string, withAPI bool) (config.Config, error) {
	cfg := config.Default()
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfg.RegisterFlags(fs)
	if withAPI {
		cfg.RegisterAPIFlag(fs)
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func printTokenSummary(out *os.File, tok *tokenstore.Token) {
	fmt.Fprintf(out, "Issuer:        %s\n", tok.Issuer)
	fmt.Fprintf(out, "Client ID:     %s\n", tok.ClientID)
	if subject := subjectOf(tok); subject != "" {
		fmt.Fprintf(out, "Subject:       %s\n", subject)
	}
	if tok.Scope != "" {
		fmt.Fprintf(out, "Scope:         %s\n", tok.Scope)
	}
	switch {
	case tok.Expiry.IsZero():
		fmt.Fprintf(out, "Expires:       unknown\n")
	case tok.Expired():
		fmt.Fprintf(out, "Expires:       %s (expired)\n", tok.Expiry.Format(time.RFC3339))
	default:
		fmt.Fprintf(out, "Expires:       %s (in %s)\n", tok.Expiry.Format(time.RFC3339), time.Until(tok.Expiry).Round(time.Second))
	}
	fmt.Fprintf(out, "Refreshable:   %t\n", tok.RefreshToken != "")
}

// subjectOf reads the "sub" claim from the ID token for display only. The
// value is never used for an authorization decision, the endpoint verifies the
// token itself.
func subjectOf(tok *tokenstore.Token) string {
	raw := tok.IDToken
	if raw == "" {
		raw = tok.AccessToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Subject           string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	for _, candidate := range []string{claims.PreferredUsername, claims.Email, claims.Subject} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `oidc-cli calls an OIDC protected HTTP endpoint.

Usage:
  oidc-cli <command> [flags]

Commands:
  call [url]   GET the protected endpoint, logging in when necessary
  login        run the browser login and cache the token
  logout       delete the cached token
  token        print a valid access token, logging in when necessary
  status       show the cached token without contacting the provider
  serve        run the example protected endpoint locally
  version      print the version

Run "oidc-cli <command> -h" for the flags of a command. Every flag also has an
OIDCCLI_ environment variable, for example OIDCCLI_ISSUER for --issuer.
`)
}
