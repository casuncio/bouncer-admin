package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if verifier == "" {
		t.Fatal("GeneratePKCE() verifier is empty")
	}
	if challenge == "" {
		t.Fatal("GeneratePKCE() challenge is empty")
	}

	if _, err := base64.RawURLEncoding.DecodeString(verifier); err != nil {
		t.Errorf("verifier is not raw base64url: %v", err)
	}

	sum := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want S256(%q) = %q", challenge, verifier, wantChallenge)
	}
}

func TestGeneratePKCE_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		verifier, _, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE() error = %v", err)
		}
		if _, ok := seen[verifier]; ok {
			t.Fatalf("GeneratePKCE() produced duplicate verifier %q", verifier)
		}
		seen[verifier] = struct{}{}
	}
}

func TestGenerateState(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() error = %v", err)
	}
	if state == "" {
		t.Fatal("GenerateState() returned empty string")
	}
	if _, err := base64.RawURLEncoding.DecodeString(state); err != nil {
		t.Errorf("state is not raw base64url: %v", err)
	}
}

func TestGenerateState_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		state, err := GenerateState()
		if err != nil {
			t.Fatalf("GenerateState() error = %v", err)
		}
		if _, ok := seen[state]; ok {
			t.Fatalf("GenerateState() produced duplicate state %q", state)
		}
		seen[state] = struct{}{}
	}
}

func TestAdminClaimsHasRole(t *testing.T) {
	full := &AdminClaims{
		RealmAccess: RealmRole{Roles: []string{"offline_access", "policy-admin"}},
		ResourceAccess: map[string]ClientRole{
			"bouncer-admin-gui": {Roles: []string{"viewer", "editor"}},
			"other-client":      {Roles: []string{"admin"}},
		},
		Groups: []string{"/admins", "ops"},
	}

	tests := []struct {
		name     string
		claims   *AdminClaims
		clientID string
		role     string
		want     bool
	}{
		{name: "realm role", claims: full, clientID: "bouncer-admin-gui", role: "policy-admin", want: true},
		{name: "client role", claims: full, clientID: "bouncer-admin-gui", role: "editor", want: true},
		{name: "group", claims: full, clientID: "bouncer-admin-gui", role: "/admins", want: true},
		{name: "role on other client", claims: full, clientID: "other-client", role: "admin", want: true},
		{name: "other client role ignored", claims: full, clientID: "bouncer-admin-gui", role: "admin", want: false},
		{name: "unknown role", claims: full, clientID: "bouncer-admin-gui", role: "superuser", want: false},
		{name: "empty claims", claims: &AdminClaims{}, clientID: "bouncer-admin-gui", role: "policy-admin", want: false},
		{
			name:     "realm only",
			claims:   &AdminClaims{RealmAccess: RealmRole{Roles: []string{"policy-admin"}}},
			clientID: "bouncer-admin-gui",
			role:     "policy-admin",
			want:     true,
		},
		{
			name: "client only",
			claims: &AdminClaims{ResourceAccess: map[string]ClientRole{
				"bouncer-admin-gui": {Roles: []string{"editor"}},
			}},
			clientID: "bouncer-admin-gui",
			role:     "editor",
			want:     true,
		},
		{
			name:     "wrong client id",
			claims:   &AdminClaims{ResourceAccess: map[string]ClientRole{"bouncer-admin-gui": {Roles: []string{"editor"}}}},
			clientID: "someone-else",
			role:     "editor",
			want:     false,
		},
		{
			name:     "groups only",
			claims:   &AdminClaims{Groups: []string{"ops"}},
			clientID: "bouncer-admin-gui",
			role:     "ops",
			want:     true,
		},
		{
			name:     "nil resource access",
			claims:   &AdminClaims{RealmAccess: RealmRole{Roles: []string{"r"}}},
			clientID: "c",
			role:     "r",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.HasRole(tt.clientID, tt.role); got != tt.want {
				t.Errorf("HasRole(%q, %q) = %v, want %v", tt.clientID, tt.role, got, tt.want)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	env := setupTestOIDC(t)
	a := env.authenticator

	if a.Provider == nil {
		t.Fatal("Provider is nil")
	}
	if a.Verifier == nil {
		t.Fatal("Verifier is nil")
	}
	if a.OAuth2Config.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", a.OAuth2Config.ClientID, testClientID)
	}
	if a.OAuth2Config.ClientSecret != "test-secret" {
		t.Errorf("ClientSecret = %q, want test-secret", a.OAuth2Config.ClientSecret)
	}
	if a.OAuth2Config.RedirectURL != testRedirectURL {
		t.Errorf("RedirectURL = %q, want %q", a.OAuth2Config.RedirectURL, testRedirectURL)
	}
	if a.OAuth2Config.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Errorf("AuthStyle = %v, want AuthStyleInParams", a.OAuth2Config.Endpoint.AuthStyle)
	}
	if a.OAuth2Config.Endpoint.AuthURL == "" {
		t.Error("AuthURL is empty")
	}
	if a.OAuth2Config.Endpoint.TokenURL == "" {
		t.Error("TokenURL is empty")
	}
	if !contains(a.OAuth2Config.Scopes, oidc.ScopeOpenID) || !contains(a.OAuth2Config.Scopes, "profile") || !contains(a.OAuth2Config.Scopes, "email") {
		t.Errorf("Scopes = %v, want openid, profile, email", a.OAuth2Config.Scopes)
	}
}

func TestNewAuthenticator_DiscoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	_, err := NewAuthenticator(context.Background(), Config{
		IssuerURL: srv.URL,
		ClientID:  testClientID,
	})
	if err == nil {
		t.Fatal("NewAuthenticator() error = nil, want discovery failure")
	}
	if !strings.Contains(err.Error(), "failed to discover oidc provider") {
		t.Errorf("error = %v, want wrapped discovery error", err)
	}
}

func TestAuthenticatorAuthCodeURL(t *testing.T) {
	env := setupTestOIDC(t)

	const state = "csrf-state"
	const challenge = "pkce-challenge"

	rawURL := env.authenticator.AuthCodeURL(state, challenge)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("AuthCodeURL produced invalid URL %q: %v", rawURL, err)
	}

	q := parsed.Query()
	if got := q.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if got := q.Get("code_challenge"); got != challenge {
		t.Errorf("code_challenge = %q, want %q", got, challenge)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if got := q.Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q, want %q", got, testClientID)
	}
	if got := q.Get("redirect_uri"); got != testRedirectURL {
		t.Errorf("redirect_uri = %q, want %q", got, testRedirectURL)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope = %q, want to contain openid", q.Get("scope"))
	}
}

func TestAuthenticatorExchange(t *testing.T) {
	env := setupTestOIDC(t)

	var got url.Values
	env.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		got = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     env.idToken(nil),
		})
	}

	token, err := env.authenticator.Exchange(context.Background(), "auth-code", "pkce-verifier")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if token.AccessToken != "exchanged-access" {
		t.Errorf("AccessToken = %q, want exchanged-access", token.AccessToken)
	}
	if got.Get("code") != "auth-code" {
		t.Errorf("token request code = %q, want auth-code", got.Get("code"))
	}
	if got.Get("code_verifier") != "pkce-verifier" {
		t.Errorf("token request code_verifier = %q, want pkce-verifier", got.Get("code_verifier"))
	}
	if got.Get("client_id") != testClientID {
		t.Errorf("token request client_id = %q, want %q", got.Get("client_id"), testClientID)
	}
}

func TestAuthenticatorExchange_Error(t *testing.T) {
	env := setupTestOIDC(t)
	env.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}

	_, err := env.authenticator.Exchange(context.Background(), "bad-code", "verifier")
	if err == nil {
		t.Fatal("Exchange() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "failed to exchange authorization code") {
		t.Errorf("error = %v, want wrapped exchange error", err)
	}
}

func TestAuthenticatorVerifyIDToken(t *testing.T) {
	env := setupTestOIDC(t)

	raw := env.idToken(map[string]any{
		"realm_access": map[string]any{
			"roles": []string{"policy-admin"},
		},
		"resource_access": map[string]any{
			testClientID: map[string]any{
				"roles": []string{"editor"},
			},
		},
		"groups": []string{"ops"},
	})

	idToken, claims, err := env.authenticator.VerifyIDToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("VerifyIDToken() error = %v", err)
	}
	if idToken == nil {
		t.Fatal("ID token is nil")
	}
	if idToken.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", idToken.Subject, testSubject)
	}
	if claims.Email != "admin@example.com" {
		t.Errorf("Email = %q, want admin@example.com", claims.Email)
	}
	if claims.PreferredUsername != "admin" {
		t.Errorf("PreferredUsername = %q, want admin", claims.PreferredUsername)
	}
	if !claims.HasRole(testClientID, "policy-admin") {
		t.Error("expected realm role policy-admin")
	}
	if !claims.HasRole(testClientID, "editor") {
		t.Error("expected client role editor")
	}
	if !claims.HasRole(testClientID, "ops") {
		t.Error("expected group ops")
	}
}

func TestAuthenticatorVerifyIDToken_Invalid(t *testing.T) {
	env := setupTestOIDC(t)

	tests := []struct {
		name  string
		token string
	}{
		{name: "malformed", token: "not-a-jwt"},
		{name: "empty", token: ""},
		{name: "expired", token: env.idToken(map[string]any{
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		})},
		{name: "wrong audience", token: env.idToken(map[string]any{"aud": "someone-else"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := env.authenticator.VerifyIDToken(context.Background(), tt.token)
			if err == nil {
				t.Fatal("VerifyIDToken() error = nil, want failure")
			}
			if !strings.Contains(err.Error(), "failed to verify raw ID token") {
				t.Errorf("error = %v, want wrapped verify error", err)
			}
		})
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
