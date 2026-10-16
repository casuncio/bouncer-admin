package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/casuncio/bouncer-admin/internal/auth"
	"github.com/casuncio/bouncer-admin/internal/authtest"
)

func newTestHandler(t *testing.T) (http.Handler, *authtest.AuthEnv) {
	t.Helper()

	env := authtest.SetupAuth(t)
	return NewServer(env.Authenticator), env
}

const policyAdminRole = "PolicyAdmin"

func TestPoliciesAccess(t *testing.T) {
	handler, env := newTestHandler(t)

	adminToken := env.IDToken(map[string]any{
		"realm_access": map[string]any{
			"roles": []string{policyAdminRole},
		},
	})
	noRoleToken := env.IDToken(nil)

	tests := []struct {
		name       string
		method     string
		path       string
		setup      func(*http.Request)
		wantStatus int
		wantBody   string
	}{
		{
			name:       "POST missing token",
			method:     http.MethodPost,
			path:       "/api/policies",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Missing authorization token",
		},
		{
			name:   "POST invalid token",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer not-a-jwt")
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Invalid or expired token",
		},
		{
			name:   "POST missing role",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+noRoleToken)
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "Unauthorized policy administrator",
		},
		{
			name:   "POST valid bearer token",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+adminToken)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "POST valid session cookie",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  auth.SessionCookieName,
					Value: env.SealSession(t, auth.TokenSet{IDToken: adminToken}),
				})
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "POST raw token in session cookie",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: adminToken})
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Invalid or expired token",
		},
		{
			name:   "POST groups claim",
			method: http.MethodPost,
			path:   "/api/policies",
			setup: func(r *http.Request) {
				tok := env.IDToken(map[string]any{
					"groups": []string{policyAdminRole},
				})
				r.Header.Set("Authorization", "Bearer "+tok)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET method not allowed",
			method:     http.MethodGet,
			path:       "/api/policies",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "DELETE valid bearer token",
			method: http.MethodDelete,
			path:   "/api/policies/policy-1",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+adminToken)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST on delete path method not allowed",
			method:     http.MethodPost,
			path:       "/api/policies/policy-1",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.setup != nil {
				tt.setup(req)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %q", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {
	handler, env := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body = %q", rec.Code, http.StatusFound, rec.Body.String())
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	stateParam := q.Get("state")
	if stateParam == "" {
		t.Error("redirect URL has no state parameter")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}

	cookies := rec.Result().Cookies()
	stateCookie := findCookie(cookies, auth.StateCookieName)
	if stateCookie == nil {
		t.Fatal("auth_state cookie not set")
	}
	if stateCookie.Value != stateParam {
		t.Errorf("auth_state = %q, want the state sent to the IdP %q", stateCookie.Value, stateParam)
	}
	if !stateCookie.HttpOnly {
		t.Error("auth_state should be HttpOnly")
	}
	if stateCookie.Path != "/auth/callback" {
		t.Errorf("auth_state Path = %q, want /auth/callback", stateCookie.Path)
	}
	if stateCookie.MaxAge != 300 {
		t.Errorf("auth_state MaxAge = %d, want 300", stateCookie.MaxAge)
	}

	verifierCookie := findCookie(cookies, auth.PKCEVerifierCookieName)
	if verifierCookie == nil {
		t.Fatal("pkce_verifier cookie not set")
	}
	if !verifierCookie.HttpOnly {
		t.Error("pkce_verifier should be HttpOnly")
	}
	if verifierCookie.Path != "/auth/callback" {
		t.Errorf("pkce_verifier Path = %q, want /auth/callback", verifierCookie.Path)
	}
	if verifierCookie.MaxAge != 300 {
		t.Errorf("pkce_verifier MaxAge = %d, want 300", verifierCookie.MaxAge)
	}

	// The cookie must hold the sealed verifier whose challenge went to the
	// IdP, not the plaintext verifier.
	verifier, err := env.SessionCodec.OpenValue(verifierCookie.Value)
	if err != nil {
		t.Fatalf("pkce_verifier is not sealed: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if got, want := base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"); got != want {
		t.Errorf("code_challenge = %q, want SHA-256 of the sealed verifier %q", want, got)
	}
}

func TestHandleCallback(t *testing.T) {
	handler, env := newTestHandler(t)

	const state = "test-state"

	t.Run("missing state cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rec.Body.String(), "Invalid state parameter") {
			t.Errorf("body = %q, want invalid state error", rec.Body.String())
		}
	})

	t.Run("state cookie mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state=attacker-state", nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rec.Body.String(), "Invalid state parameter") {
			t.Errorf("body = %q, want invalid state error", rec.Body.String())
		}
	})

	t.Run("missing state query parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code", nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rec.Body.String(), "Invalid state parameter") {
			t.Errorf("body = %q, want invalid state error", rec.Body.String())
		}
	})

	t.Run("missing verifier cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d; body = %q", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "Missing authorization code or verifier") {
			t.Errorf("body = %q", rec.Body.String())
		}
	})

	t.Run("raw verifier in cookie is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		req.AddCookie(&http.Cookie{Name: auth.PKCEVerifierCookieName, Value: "raw-verifier"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d; body = %q", rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "Missing authorization code or verifier") {
			t.Errorf("body = %q, want missing verifier error", rec.Body.String())
		}
	})

	t.Run("exchange failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state, nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		req.AddCookie(&http.Cookie{Name: auth.PKCEVerifierCookieName, Value: env.SealValue(t, "verifier")})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %q", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	})

	t.Run("sets admin_session, clears login cookies, and redirects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: auth.StateCookieName, Value: state})
		req.AddCookie(&http.Cookie{Name: auth.PKCEVerifierCookieName, Value: env.SealValue(t, "verifier")})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d; body = %q", rec.Code, http.StatusFound, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("Location = %q, want /", loc)
		}

		cookies := rec.Result().Cookies()

		// The state and verifier are single-use: both flow cookies must be
		// deleted alongside the login completing.
		for _, name := range []string{auth.StateCookieName, auth.PKCEVerifierCookieName} {
			c := findCookie(cookies, name)
			if c == nil {
				t.Errorf("%s cookie not set for deletion", name)
				continue
			}
			if c.MaxAge != -1 {
				t.Errorf("%s MaxAge = %d, want deletion (-1)", name, c.MaxAge)
			}
		}

		session := findCookie(cookies, auth.SessionCookieName)
		if session == nil {
			t.Fatal("admin_session cookie not set")
		}
		if session.Value == "" {
			t.Error("admin_session cookie is empty")
		}
		if session.Path != "/" {
			t.Errorf("admin_session Path = %q, want /", session.Path)
		}
		if !session.HttpOnly {
			t.Error("admin_session should be HttpOnly")
		}
		if session.SameSite != http.SameSiteLaxMode {
			t.Errorf("admin_session SameSite = %v, want Lax", session.SameSite)
		}

		// The cookie must hold a sealed token set, not the raw ID token.
		set, err := env.SessionCodec.Open(session.Value)
		if err != nil {
			t.Fatalf("open admin_session cookie: %v", err)
		}
		if set.AccessToken != "test-access-token" {
			t.Errorf("sealed AccessToken = %q, want test-access-token", set.AccessToken)
		}
		if set.RefreshToken != "test-refresh" {
			t.Errorf("sealed RefreshToken = %q, want test-refresh", set.RefreshToken)
		}
		idToken, _, err := env.Authenticator.VerifyIDToken(context.Background(), set.IDToken)
		if err != nil {
			t.Fatalf("verify sealed ID token: %v", err)
		}
		if idToken.Subject != authtest.Subject {
			t.Errorf("sealed ID token subject = %q, want %q", idToken.Subject, authtest.Subject)
		}
	})
}

func TestLoginCallbackFlow(t *testing.T) {
	handler, _ := newTestHandler(t)

	// /auth/login mints the state and verifier cookies and redirects to the IdP.
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginRec.Code, http.StatusFound)
	}

	loc, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	state := loc.Query().Get("state")

	// The IdP redirects back with the code; the flow cookies from /auth/login
	// must satisfy the callback's state and verifier checks.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil)
	for _, c := range loginRec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d; body = %q", rec.Code, http.StatusFound, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	if findCookie(rec.Result().Cookies(), auth.SessionCookieName) == nil {
		t.Error("admin_session cookie not set after login flow")
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
