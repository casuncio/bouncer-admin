package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/casuncio/bouncer-admin/internal/auth"
	"github.com/casuncio/bouncer-admin/internal/authtest"
)

func TestRequireRole(t *testing.T) {
	env := authtest.SetupAuth(t)
	const requiredRole = "policy-admin"

	validToken := env.IDToken(map[string]any{
		"realm_access": map[string]any{
			"roles": []string{requiredRole},
		},
	})
	noRoleToken := env.IDToken(nil)

	tests := []struct {
		name       string
		setup      func(*http.Request)
		wantStatus int
		wantBody   string
		wantNext   bool
	}{
		{
			name:       "missing token",
			setup:      func(*http.Request) {},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Missing authorization token",
		},
		{
			name: "invalid token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer not-a-jwt")
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Invalid or expired token",
		},
		{
			name: "expired token",
			setup: func(r *http.Request) {
				tok := env.IDToken(map[string]any{
					"exp": time.Now().Add(-time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(),
				})
				r.Header.Set("Authorization", "Bearer "+tok)
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Invalid or expired token",
		},
		{
			name: "missing role",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+noRoleToken)
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "Unauthorized policy administrator",
		},
		{
			name: "valid bearer token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+validToken)
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		{
			name: "valid session cookie",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: validToken})
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				claims, ok := r.Context().Value(auth.ClaimsContextKey).(*auth.AdminClaims)
				if !ok || claims == nil {
					t.Error("expected AdminClaims in request context")
					http.Error(w, "missing claims", http.StatusInternalServerError)
					return
				}
				if claims.Subject != authtest.Subject {
					t.Errorf("claims.Subject = %q, want %q", claims.Subject, authtest.Subject)
				}
				if !claims.HasRole(authtest.ClientID, requiredRole) {
					t.Errorf("injected claims missing role %q", requiredRole)
				}
				w.WriteHeader(http.StatusNoContent)
			})

			handler := auth.RequireRole(env.Authenticator, authtest.ClientID, requiredRole)(next)
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			tt.setup(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want to contain %q", rec.Body.String(), tt.wantBody)
			}
			if called != tt.wantNext {
				t.Errorf("next called = %v, want %v", called, tt.wantNext)
			}
		})
	}
}
