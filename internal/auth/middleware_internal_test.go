package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractToken(t *testing.T) {
	codec, err := NewSessionCodec("internal-test-secret")
	if err != nil {
		t.Fatalf("NewSessionCodec: %v", err)
	}

	sealed, err := codec.Seal(TokenSet{IDToken: "cookie-token"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := []struct {
		name    string
		setup   func(*http.Request)
		want    string
		wantErr bool
	}{
		{
			name: "bearer header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer abc.def.ghi")
			},
			want: "abc.def.ghi",
		},
		{
			name: "sealed session cookie",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sealed})
			},
			want: "cookie-token",
		},
		{
			name: "raw token in session cookie is rejected",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-token"})
			},
			wantErr: true,
		},
		{
			name: "undecryptable blob in session cookie is rejected",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: strings.Repeat("A", 40)})
			},
			wantErr: true,
		},
		{
			name: "tampered session cookie is rejected",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sealed[:len(sealed)-4]})
			},
			wantErr: true,
		},
		{
			name: "bearer takes precedence over cookie",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer header-token")
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sealed})
			},
			want: "header-token",
		},
		{
			name: "non-bearer header falls back to cookie",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sealed})
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
			got, err := extractToken(req, codec)
			if got != tt.want {
				t.Errorf("extractToken() = %q, want %q", got, tt.want)
			}
			if tt.wantErr != (err != nil) {
				t.Errorf("extractToken() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("cookie without codec is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sealed})
		got, err := extractToken(req, nil)
		if got != "" {
			t.Errorf("extractToken() = %q, want empty", got)
		}
		if err == nil {
			t.Error("extractToken() err = nil, want failure")
		}
	})
}
