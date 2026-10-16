package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

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

	// Public Auth Endpoints
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/callback", s.handleCallback)

	// Protected Policy Admin Endpoints
	adminMiddleware := auth.RequireRole(authenticator, "bouncer-admin-gui", "PolicyAdmin")

	mux.Handle("POST /api/policies", adminMiddleware(http.HandlerFunc(s.handleUpsertPolicy)))
	mux.Handle("DELETE /api/policies/{id}", adminMiddleware(http.HandlerFunc(s.handleDeletePolicy)))

	return mux
}

// Handlers

// /auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	slog.Info("Login request recieved")

	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		http.Error(w, "Failed to start login", http.StatusInternalServerError)
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		http.Error(w, "Failed to start login", http.StatusInternalServerError)
		return
	}

	// The PKCE verifier must never leave the server in plaintext.
	sealedVerifier, err := s.auth.Sessions.SealValue(verifier)
	if err != nil {
		http.Error(w, "Failed to start login", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.PKCEVerifierCookieName,
		Value:    sealedVerifier,
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	// The state cookie lets /auth/callback tie the callback back to this
	// login attempt; without it the flow is open to login CSRF.
	http.SetCookie(w, &http.Cookie{
		Name:     auth.StateCookieName,
		Value:    state,
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
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

	// CSRF: the state parameter must match the value /auth/login stored in
	// the auth_state cookie, compared in constant time so mismatching
	// callbacks leak nothing about the expected value.
	stateCookie, err := r.Cookie(auth.StateCookieName)
	if err != nil {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie(auth.PKCEVerifierCookieName)
	if err != nil {
		http.Error(w, "Missing authorization code or verifier", http.StatusBadRequest)
		return
	}
	verifier, err := s.auth.Sessions.OpenValue(verifierCookie.Value)
	if err != nil {
		http.Error(w, "Missing authorization code or verifier", http.StatusBadRequest)
		return
	}

	token, err := s.auth.Exchange(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, "Token exchange failed:"+err.Error(), http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "Missing ID token", http.StatusUnauthorized)
		return
	}

	idToken, _, err := s.auth.VerifyIDToken(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	maxAge := int(time.Until(idToken.Expiry).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	// Seal the full token set into the session cookie: the raw ID token must
	// never leave the server in plaintext.
	sealed, err := s.auth.Sessions.Seal(auth.TokenSet{
		IDToken:      rawIDToken,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	})
	if err != nil {
		http.Error(w, "Failed to establish session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    sealed,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})

	// The state and verifier are single-use; clear both now that the login
	// completed.
	for _, name := range []string{auth.StateCookieName, auth.PKCEVerifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/auth/callback",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleUpsertPolicy(w http.ResponseWriter, r *http.Request) {
	// Stub
	slog.Info("UpsertPolicy request Received")
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	// Stub
	slog.Info("DeletePolicy request Received")
}
