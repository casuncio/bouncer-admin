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
}

// SetupAuth starts a mock OIDC issuer and returns it paired with an
// Authenticator discovered from that issuer via OIDC discovery.
func SetupAuth(t *testing.T) *AuthEnv {
	t.Helper()

	env := Setup(t)
	authenticator, err := auth.NewAuthenticator(context.Background(), auth.Config{
		IssuerURL:    env.Server.URL,
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		RedirectURL:  RedirectURL,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	return &AuthEnv{Env: env, Authenticator: authenticator}
}
