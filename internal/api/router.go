package api

import (
	"log/slog"
	"net/http"

	"github.com/casuncio/bouncer-admin/internal/auth"
)

type Server struct {
	auth *auth.Authenticator
}

func NewServer(authenticator *auth.Authenticator) http.Handler {
	s := &Server{
		auth: authenticator,
	}

	mux := http.NewServeMux()

	// Register Handlers
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/callback", s.handleCallback)

	return mux
}

// Handlers

// /auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	slog.Info("Login request recieved")

	verifier, challenge, _ := auth.GeneratePKCE()

	state, _ := auth.GenerateState()

	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    verifier,
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   300,
	})

	redirectURL := s.auth.AuthCodeURL(state, challenge)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// /auth/callback
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	// PROOF
	slog.Info("Callback hit", "full_url", r.URL.String(), "code_length", len(code))

	cookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		http.Error(w, "Missing authorization code or verifier", http.StatusBadRequest)
		return
	}

	token, err := s.auth.Exchange(r.Context(), code, cookie.Value)
	if err != nil {
		http.Error(w, "Token exchange failed:"+err.Error(), http.StatusUnauthorized)
		return
	}

	// Process token
	_ = token
}
