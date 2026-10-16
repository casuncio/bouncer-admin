# Testing

All testing documentation lives here: the unit test harness, the local Dex IdP, and live endpoint checks against the admin API.

## Unit tests

Unit tests need no external services. The shared harness in `internal/authtest` starts an in-process OIDC issuer (built on `go-oidc/v3/oidc/oidctest`) that signs real ID tokens:

* `authtest.Setup(t)` — mock issuer plus an `Env` for minting ID tokens and intercepting token requests
* `authtest.SetupAuth(t)` — the same issuer paired with a fully discovered `auth.Authenticator` (and the `SessionCodec` used to seal `admin_session` cookies)

The `internal/auth` and `internal/api` suites both build on it, and `internal/auth/session_test.go` covers the AES-256-GCM codec that seals the session cookie (round trips, nonce uniqueness, tamper and wrong-key rejection).

```bash
go test ./...
```

Authorized **200** responses are asserted here: the mock issuer mints ID tokens carrying the `PolicyAdmin` role (realm role, client role, or `groups` claim), which Dex's local users cannot have.

## Local IdP with Dex

For live OIDC testing, run [Dex](https://github.com/dexidp/dex) with the pre-configured test IdP from `internal/auth/testdata/dex.yaml`.

Start the container from the root of the repo:

```bash
docker run --rm -d \
  --name dex-oidc-test \
  -p 5556:5556 \
  -v "$(pwd)/internal/auth/testdata/dex.yaml":/etc/dex/config.docker.yaml \
  ghcr.io/dexidp/dex:v2.41.0
```

Stop the container:

```bash
docker stop dex-oidc-test
```

The config registers the `bouncer-admin-gui` client (redirect URI `http://localhost:8080/auth/callback`) and a test user: `admin@example.com` / `password`.

## Session secret

The `admin_session` cookie is sealed with an AES-256-GCM key derived from `SESSION_SECRET`:

* **Unset (local dev):** the server generates an ephemeral key at startup and logs a warning — `go run ./cmd/bouncer-admin` stays zero-config, but every restart invalidates sessions.
* **Real deployments:** set a stable, high-entropy secret:

```bash
export SESSION_SECRET="$(openssl rand -base64 32)"
```

## Testing `/api/policies`

Policy admin routes require a verified ID token and the `PolicyAdmin` role on client `bouncer-admin-gui` (realm role, client role, or `groups` claim). Allowed methods are `POST /api/policies` and `DELETE /api/policies/{id}`.

**200 (authorized) is covered by unit tests**, not live Dex. Dex's local password connector does not emit `realm_access`, `resource_access`, or `groups`, so a real Dex ID token verifies and then returns **403**.

Live checks against Dex (start Dex as above, then `go run ./cmd/bouncer-admin`):

```bash
# 405 — GET is not allowed
curl -i http://127.0.0.1:8080/api/policies

# 401 — no token
curl -i -X POST http://127.0.0.1:8080/api/policies

# 401 — invalid token
curl -i -X POST -H 'Authorization: Bearer not-a-jwt' http://127.0.0.1:8080/api/policies
```

Browser login sets an `admin_session` cookie on `/auth/callback`. The cookie does **not** hold the raw ID token — it holds an AES-256-GCM-sealed token set (ID + access + refresh tokens), so its value is opaque. Dex tokens still lack `PolicyAdmin`, so the API returns **403**:

1. Open `http://localhost:8080/auth/login`
2. Sign in as `admin@example.com` / `password`
3. Copy the full `admin_session` cookie value from the callback response (or browser storage) and replay it:

```bash
curl -i -X POST --cookie 'admin_session=<cookie value>' http://127.0.0.1:8080/api/policies
# → 403 Unauthorized policy administrator
```

Password grant (no browser) for a **403** Bearer token:

```bash
# client_id is public: base64("bouncer-admin-gui:")
TOKEN=$(curl -sS -X POST 'http://127.0.0.1:5556/dex/token' \
  -H 'Authorization: Basic Ym91bmNlci1hZG1pbi1ndWk6' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'username=admin@example.com' \
  --data-urlencode 'password=password' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id_token"])')

curl -i -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/policies
# → 403 Unauthorized policy administrator
```

The session cookie must be encrypted: a raw ID token replayed as `admin_session` cannot be decrypted and is rejected like any invalid token (a sealed cookie from step 3 above still works):

```bash
curl -i -X POST --cookie "admin_session=$TOKEN" http://127.0.0.1:8080/api/policies
# → 401 Invalid or expired token
```
