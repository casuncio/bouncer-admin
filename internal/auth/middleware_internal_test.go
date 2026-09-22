package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
			setup: func(*http.Request) {},
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
