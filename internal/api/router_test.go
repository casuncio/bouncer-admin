package api

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/casuncio/bouncer-admin/internal/auth"
	"golang.org/x/oauth2"
)

func testAuthenticator(tokenURL string) *auth.Authenticator {
	return &auth.Authenticator{
		OAuth2Config: oauth2.Config{
			ClientID:     "bouncer-admin-gui",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   "http://idp.example/auth",
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
}

func TestNewServer_UnknownRoute(t *testing.T) {
	handler := NewServer(testAuthenticator("http://idp.example/token"))
	req := httptest.NewRequest(http.MethodGet, "/not-found", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleLogin(t *testing.T) {
	handler := NewServer(testAuthenticator("http://idp.example/token"))
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	var verifierCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "pkce_verifier" {
			verifierCookie = c
			break
		}
	}
	if verifierCookie == nil {
		t.Fatal("missing pkce_verifier cookie")
	}
	if verifierCookie.Path != "/auth/callback" {
		t.Errorf("cookie Path = %q, want /auth/callback", verifierCookie.Path)
	}
	if !verifierCookie.HttpOnly {
		t.Error("cookie HttpOnly = false, want true")
	}
	if verifierCookie.Secure {
		t.Error("cookie Secure = true, want false for non-TLS request")
	}
	if verifierCookie.MaxAge != 300 {
		t.Errorf("cookie MaxAge = %d, want 300", verifierCookie.MaxAge)
	}
	if verifierCookie.Value == "" {
		t.Fatal("cookie value is empty")
	}

	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("invalid redirect Location %q: %v", location, err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != "http://idp.example/auth" {
		t.Errorf("redirect host/path = %s://%s%s, want http://idp.example/auth", parsed.Scheme, parsed.Host, parsed.Path)
	}

	q := parsed.Query()
	sum := sha256.Sum256([]byte(verifierCookie.Value))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := q.Get("code_challenge"); got != wantChallenge {
		t.Errorf("code_challenge = %q, want %q (S256 of cookie verifier)", got, wantChallenge)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if q.Get("state") == "" {
		t.Error("state query param is empty")
	}
	if q.Get("client_id") != "bouncer-admin-gui" {
		t.Errorf("client_id = %q, want bouncer-admin-gui", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:8080/auth/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
}

func TestHandleLogin_SecureCookieOverTLS(t *testing.T) {
	handler := NewServer(testAuthenticator("http://idp.example/token"))
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var verifierCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "pkce_verifier" {
			verifierCookie = c
			break
		}
	}
	if verifierCookie == nil {
		t.Fatal("missing pkce_verifier cookie")
	}
	if !verifierCookie.Secure {
		t.Error("cookie Secure = false, want true for TLS request")
	}
}

func TestHandleCallback_MissingVerifierCookie(t *testing.T) {
	handler := NewServer(testAuthenticator("http://idp.example/token"))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "Missing authorization code or verifier") {
		t.Errorf("body = %q, want missing verifier error", rec.Body.String())
	}
}

func TestHandleCallback_ExchangeFailure(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	t.Cleanup(tokenSrv.Close)

	handler := NewServer(testAuthenticator(tokenSrv.URL))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=bad-code", nil)
	req.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "verifier"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), "Token exchange failed") {
		t.Errorf("body = %q, want token exchange error", rec.Body.String())
	}
}

func TestHandleCallback_Success(t *testing.T) {
	var got url.Values
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		got = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	handler := NewServer(testAuthenticator(tokenSrv.URL))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code", nil)
	req.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "pkce-verifier"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got.Get("code") != "auth-code" {
		t.Errorf("token request code = %q, want auth-code", got.Get("code"))
	}
	if got.Get("code_verifier") != "pkce-verifier" {
		t.Errorf("token request code_verifier = %q, want pkce-verifier", got.Get("code_verifier"))
	}
}
