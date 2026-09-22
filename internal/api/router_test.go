package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: adminToken})
			},
			wantStatus: http.StatusOK,
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

func TestHandleCallback(t *testing.T) {
	handler, _ := newTestHandler(t)

	t.Run("missing verifier cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rec.Body.String(), "Missing authorization code or verifier") {
			t.Errorf("body = %q", rec.Body.String())
		}
	})

	t.Run("exchange failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		req.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "verifier"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %q", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	})

	t.Run("sets admin_session and redirects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code", nil)
		req.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "verifier"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d; body = %q", rec.Code, http.StatusFound, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("Location = %q, want /", loc)
		}

		cookies := rec.Result().Cookies()
		var session *http.Cookie
		for _, c := range cookies {
			if c.Name == "admin_session" {
				session = c
				break
			}
		}
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
	})
}
