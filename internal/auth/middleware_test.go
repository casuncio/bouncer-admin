package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*http.Request)
		want  string
	}{
		{
			name: "bearer header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer abc.def.ghi")
			},
			want: "abc.def.ghi",
		},
		{
			name: "session cookie",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "cookie-token"})
			},
			want: "cookie-token",
		},
		{
			name: "bearer takes precedence over cookie",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer header-token")
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "cookie-token"})
			},
			want: "header-token",
		},
		{
			name: "non-bearer header falls back to cookie",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "cookie-token"})
			},
			want: "cookie-token",
		},
		{
			name:  "missing",
			setup: func(r *http.Request) {},
			want:  "",
		},
		{
			name: "empty bearer",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
			want: "",
		},
		{
			name: "unrelated cookie ignored",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "other", Value: "nope"})
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setup(req)
			if got := extractToken(req); got != tt.want {
				t.Errorf("extractToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	env := setupTestOIDC(t)
	const requiredRole = "policy-admin"

	validToken := env.idToken(map[string]any{
		"realm_access": map[string]any{
			"roles": []string{requiredRole},
		},
	})
	noRoleToken := env.idToken(nil)

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
				tok := env.idToken(map[string]any{
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
				claims, ok := r.Context().Value(ClaimsContextKey).(*AdminClaims)
				if !ok || claims == nil {
					t.Error("expected AdminClaims in request context")
					http.Error(w, "missing claims", http.StatusInternalServerError)
					return
				}
				if claims.Subject != testSubject {
					t.Errorf("claims.Subject = %q, want %q", claims.Subject, testSubject)
				}
				if !claims.HasRole(testClientID, requiredRole) {
					t.Errorf("injected claims missing role %q", requiredRole)
				}
				w.WriteHeader(http.StatusNoContent)
			})

			handler := RequireRole(env.authenticator, testClientID, requiredRole)(next)
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
