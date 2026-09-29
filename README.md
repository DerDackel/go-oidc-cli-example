# oidc-cli

A small Go CLI that calls an OIDC protected HTTP endpoint.

The access token is cached in a file. When no token is cached, when the cached
token is expired and cannot be refreshed, or when the endpoint rejects it, the
CLI opens a browser, runs the OpenID Connect authorization code flow with PKCE
and stores the new token — the same pattern the AWS CLI uses for IAM Identity
Center logins.

## How the login works

1. The CLI looks for a cached token in `~/.config/oidc-cli/token.json`.
2. If the token is still valid, it is used as is.
3. If it is expired and a refresh token is present, a silent refresh is tried.
4. Otherwise the CLI starts a temporary HTTP server on `127.0.0.1`, opens the
   authorization URL in the default browser and waits for the redirect.
5. The authorization code is exchanged for tokens, the ID token is verified
   (signature, issuer, audience, nonce) and the result is written to the token
   file with `0600` permissions.

Security properties of the flow:

- **PKCE (RFC 7636)** with `S256`, so no client secret is required and an
  intercepted authorization code is useless on its own.
- **Loopback redirect (RFC 8252)**, on `127.0.0.1` with an ephemeral port by
  default, never on a public URL.
- **State parameter** bound to the single CLI invocation, checked before the
  code is accepted.
- **Nonce** in the authorization request, compared against the ID token claim.
- Token file written atomically, owner-readable only, in a `0700` directory.

## Install

```sh
go build -o oidc-cli ./cmd/oidc-cli
```

## Configure

Every flag has an `OIDCCLI_` environment variable:

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `--issuer` | `OIDCCLI_ISSUER` | OIDC issuer URL, discovery happens at `<issuer>/.well-known/openid-configuration` |
| `--client-id` | `OIDCCLI_CLIENT_ID` | client ID registered at the provider |
| `--client-secret` | `OIDCCLI_CLIENT_SECRET` | only if the provider insists on one; a CLI is a public client |
| `--scopes` | `OIDCCLI_SCOPES` | default `openid profile email offline_access` |
| `--audience` | `OIDCCLI_AUDIENCE` | extra `audience` parameter, needed by Auth0 and others to get a JWT access token for the API |
| `--redirect-port` | `OIDCCLI_REDIRECT_PORT` | fixed loopback port; `0` picks a free one |
| `--url` | `OIDCCLI_API_URL` | default endpoint for `call` |
| `--token-file` | `OIDCCLI_TOKEN_FILE` | location of the cached token |
| `--no-browser` | — | fail instead of opening a browser |

Register the redirect URI at the provider. If it allows any port on the
loopback interface, as RFC 8252 recommends, register `http://127.0.0.1/callback`
and leave `--redirect-port` at `0`. If it demands an exact URI, pick a port and
register `http://127.0.0.1:<port>/callback`.

## Use

```sh
export OIDCCLI_ISSUER=https://id.example.com/realms/demo
export OIDCCLI_CLIENT_ID=oidc-cli

oidc-cli login                                   # browser flow, cache the token
oidc-cli status                                  # what is cached, without any network call
oidc-cli call https://api.example.com/hello      # log in if needed, then GET
oidc-cli token                                   # print a valid access token
oidc-cli logout                                  # drop the cached token

curl -H "Authorization: Bearer $(oidc-cli token)" https://api.example.com/hello
```

In scripts that must not open a browser, use `--no-browser`; the CLI then fails
with a clear message instead of blocking on user interaction.

## Try it end to end

`docker-compose.yml` starts a Keycloak that already contains everything the
demo needs, and `serve` runs the example protected endpoint against it:

```sh
make keycloak-up                # or: docker compose up -d --wait
export OIDCCLI_ISSUER=http://localhost:8081/realms/demo
export OIDCCLI_CLIENT_ID=oidc-cli
export OIDCCLI_API_URL=http://localhost:8080/api/hello

oidc-cli serve --audience demo-api &   # the protected endpoint, on :8080
oidc-cli call                          # opens the browser, then GETs the endpoint
```

Log in as **demo** / **demo**. The endpoint validates the bearer token against
the JWKS of the realm and echoes the claims back. Afterwards:

```sh
oidc-cli status                 # cached token, no network call
oidc-cli logout                 # drop it and print the Keycloak logout URL
make keycloak-down              # stop Keycloak and delete its data
```

Note that the endpoint expects a **JWT** access token. Some providers, Auth0
among them, only issue an opaque access token unless an `audience` is
requested — set `--audience` in that case.

### What the compose stack contains

| | |
| --- | --- |
| Keycloak | `quay.io/keycloak/keycloak:26.4` in `start-dev` mode, published on `127.0.0.1:8081` only |
| Realm | `demo`, imported from `deploy/keycloak/demo-realm.json` at startup |
| Client `oidc-cli` | public, standard flow, PKCE method `S256` required, redirect URIs `http://127.0.0.1/*` and `http://localhost/*`, direct access grants off |
| Client `demo-api` | bearer only; it is the resource server, an audience mapper on `oidc-cli` puts it into the `aud` claim of every access token |
| User | `demo` / `demo`, `demo@example.com` |
| Admin console | <http://localhost:8081> with `admin` / `admin` |
| Access token lifetime | 300 s, so a silent refresh can be observed without waiting long |

Keycloak is published on 8081 because `oidc-cli serve` uses 8080. Since the
container port and the published port differ, `KC_HOSTNAME` pins the public URL
— it ends up in the `issuer` claim and in every URL of the discovery document,
so it must be the one the CLI dials.

The stack is a development setup: in-memory database, plain HTTP, `sslRequired`
turned off and fixed bootstrap credentials in the compose file. It is bound to
the loopback interface for that reason. Do not reuse the realm export or the
compose file for anything reachable from outside your machine.

To watch the refresh path, lower the token lifetime in the realm
(`accessTokenLifespan`), or run `oidc-cli token` again after 300 seconds: the
cached refresh token is used and no browser opens.

### Provider notes

- **Keycloak**: issuer `https://<host>/realms/<realm>`, client of type public,
  standard flow on, PKCE method `S256`, redirect URI `http://127.0.0.1/*`.
  Add an audience mapper for the resource server, as
  `deploy/keycloak/demo-realm.json` does, instead of relying on the default
  `account` audience.
- **Auth0**: issuer `https://<tenant>.eu.auth0.com/`, native application,
  `--audience https://<your-api-identifier>` to receive a JWT access token.
  Keep `offline_access` in the scopes for a refresh token.
- **Microsoft Entra ID**: issuer
  `https://login.microsoftonline.com/<tenant-id>/v2.0`, mobile and desktop
  application platform, redirect URI `http://localhost`, scope
  `openid offline_access api://<app-id>/<scope>`.

## Layout

```
cmd/oidc-cli        command line entry point and subcommands
internal/config     flags, environment variables, defaults
internal/tokenstore the cached token on disk
internal/auth       discovery, PKCE login, refresh, loopback callback
internal/api        authenticated calls, with one retry after a 401
internal/demoserver the example OIDC protected endpoint
deploy/keycloak    realm export imported by the compose stack
```

## Test

```sh
go test ./...
```
