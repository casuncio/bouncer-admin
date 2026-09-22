package auth

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
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

const (
	testClientID    = "bouncer-admin-gui"
	testRedirectURL = "http://localhost:8080/auth/callback"
	testKeyID       = "test-key"
	testSubject     = "usr-001"
)

type testOIDC struct {
	t             *testing.T
	priv          *rsa.PrivateKey
	server        *httptest.Server
	authenticator *Authenticator
	tokenHandler  http.HandlerFunc
}

func setupTestOIDC(t *testing.T) *testOIDC {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	env := &testOIDC{t: t, priv: priv}

	oidcSrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{
				PublicKey: priv.Public(),
				KeyID:     testKeyID,
				Algorithm: oidc.RS256,
			},
		},
	}

	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if env.tokenHandler != nil {
				env.tokenHandler(w, r)
				return
			}
			env.defaultTokenHandler(w, r)
			return
		}
		oidcSrv.ServeHTTP(w, r)
	}))
	t.Cleanup(env.server.Close)
	oidcSrv.SetIssuer(env.server.URL)

	authenticator, err := NewAuthenticator(context.Background(), Config{
		IssuerURL:    env.server.URL,
		ClientID:     testClientID,
		ClientSecret: "test-secret",
		RedirectURL:  testRedirectURL,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	env.authenticator = authenticator
	return env
}

func (e *testOIDC) idToken(extra map[string]any) string {
	e.t.Helper()

	claims := map[string]any{
		"iss":                e.server.URL,
		"aud":                testClientID,
		"sub":                testSubject,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"email":              "admin@example.com",
		"preferred_username": "admin",
	}
	for k, v := range extra {
		claims[k] = v
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		e.t.Fatalf("marshal ID token claims: %v", err)
	}
	return oidctest.SignIDToken(e.priv, testKeyID, oidc.RS256, string(raw))
}

func (e *testOIDC) defaultTokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Form.Get("code") == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      e.idToken(nil),
		"refresh_token": "test-refresh",
	})
}
