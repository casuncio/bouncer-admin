package authtest

import (
	"context"
	"testing"

	"github.com/casuncio/bouncer-admin/internal/auth"
)

// AuthEnv bundles a mock OIDC issuer (Env) with a bouncer-admin
// Authenticator configured against that issuer.
type AuthEnv struct {
	*Env
	Authenticator *auth.Authenticator
	SessionCodec  *auth.SessionCodec
}

// SetupAuth starts a mock OIDC issuer and returns it paired with an
// Authenticator discovered from that issuer via OIDC discovery. The
// Authenticator seals session cookies with SessionSecret.
func SetupAuth(t *testing.T) *AuthEnv {
	t.Helper()

	env := Setup(t)
	authenticator, err := auth.NewAuthenticator(context.Background(), auth.Config{
		IssuerURL:     env.Server.URL,
		ClientID:      ClientID,
		ClientSecret:  ClientSecret,
		RedirectURL:   RedirectURL,
		SessionSecret: SessionSecret,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	return &AuthEnv{
		Env:           env,
		Authenticator: authenticator,
		SessionCodec:  authenticator.Sessions,
	}
}

// SealSession seals a token set exactly the way the /auth/callback handler
// seals the admin_session cookie. Use it to mint session cookies in tests.
func (e *AuthEnv) SealSession(t *testing.T, set auth.TokenSet) string {
	t.Helper()

	sealed, err := e.SessionCodec.Seal(set)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	return sealed
}

// SealValue seals a single secret string exactly the way the /auth/login
// handler seals the pkce_verifier cookie. Use it to mint verifier cookies in
// tests.
func (e *AuthEnv) SealValue(t *testing.T, value string) string {
	t.Helper()

	sealed, err := e.SessionCodec.SealValue(value)
	if err != nil {
		t.Fatalf("seal value: %v", err)
	}
	return sealed
}
