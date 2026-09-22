package authtest

import (
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
	ClientID     = "bouncer-admin-gui"
	ClientSecret = "test-secret"
	RedirectURL  = "http://localhost:8080/auth/callback"
	KeyID        = "test-key"
	Subject      = "usr-001"
)

type Env struct {
	T            *testing.T
	Priv         *rsa.PrivateKey
	Server       *httptest.Server
	TokenHandler http.HandlerFunc
}

func Setup(t *testing.T) *Env {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	env := &Env{T: t, Priv: priv}

	oidcSrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{
				PublicKey: priv.Public(),
				KeyID:     KeyID,
				Algorithm: oidc.RS256,
			},
		},
	}

	env.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if env.TokenHandler != nil {
				env.TokenHandler(w, r)
				return
			}
			env.DefaultTokenHandler(w, r)
			return
		}
		oidcSrv.ServeHTTP(w, r)
	}))
	t.Cleanup(env.Server.Close)
	oidcSrv.SetIssuer(env.Server.URL)

	return env
}

func (e *Env) IDToken(extra map[string]any) string {
	e.T.Helper()

	claims := map[string]any{
		"iss":                e.Server.URL,
		"aud":                ClientID,
		"sub":                Subject,
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
		e.T.Fatalf("marshal ID token claims: %v", err)
	}
	return oidctest.SignIDToken(e.Priv, KeyID, oidc.RS256, string(raw))
}

func (e *Env) DefaultTokenHandler(w http.ResponseWriter, r *http.Request) {
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
		"id_token":      e.IDToken(nil),
		"refresh_token": "test-refresh",
	})
}
