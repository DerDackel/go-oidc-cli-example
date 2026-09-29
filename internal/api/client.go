// Package api calls the OIDC protected HTTP endpoint with the access token
// obtained by the auth package.
package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/DerDackel/go-oidc-cli-example/internal/auth"
)

// Client performs authenticated requests against the example endpoint.
type Client struct {
	auth *auth.Authenticator
	http *http.Client
}

// New returns a client that fetches its tokens from a.
func New(a *auth.Authenticator) *Client {
	return &Client{
		auth: a,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Response is the result of a call to the protected endpoint.
type Response struct {
	StatusCode int
	Body       []byte
}

// Get calls url with a bearer token. A 401 is retried once with a freshly
// obtained token, because the server may reject a token the CLI still
// considers valid, for example after a revocation or a clock skew.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	tok, err := c.auth.Token(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(ctx, url, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	fresh, err := c.auth.Login(ctx)
	if err != nil {
		return nil, fmt.Errorf("endpoint rejected the token and re-login failed: %w", err)
	}
	return c.do(ctx, url, fresh.AccessToken)
}

func (c *Client) do(ctx context.Context, url, accessToken string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	return &Response{StatusCode: resp.StatusCode, Body: body}, nil
}
