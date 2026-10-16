package auth

import (
	"context"
	"net/http"
	"strings"
)

// ContextKey is used for strongly-typed context injection
type ContextKey string

const ClaimsContextKey ContextKey = "admin_claims"

// RequireRole returns an HTTP middleware that enforces local JWT validation and RBAC.
func RequireRole(authenticator *Authenticator, clientID, requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// 1. Extract the JWT from the Authorization header or the sealed session cookie
			rawToken, err := extractToken(r, authenticator.Sessions)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}
			if rawToken == "" {
				http.Error(w, "Missing authorization token", http.StatusUnauthorized)
				return
			}

			// 2. Locally verify the JWT signature against the cached IdP public keys
			_, claims, err := authenticator.VerifyIDToken(r.Context(), rawToken)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// 3. Enforce Role-Based Access Control (RBAC) on the control plane
			if !claims.HasRole(clientID, requiredRole) {
				http.Error(w, "Unauthorized policy administrator", http.StatusForbidden)
				return
			}

			// 4. Inject claims into the request context for downstream handlers (e.g., Git author metadata)
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken attempts to pull the Bearer token from the header, falling back
// to the ID token sealed inside the session cookie.
//
// A session cookie that cannot be decrypted yields an error so the middleware
// answers with "Invalid or expired token" instead of "Missing authorization
// token": callers must not be able to distinguish a tampered cookie from a bad
// JWT.
func extractToken(r *http.Request, sessions *SessionCodec) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), nil
	}

	// Fallback for browser-based UI administration: the cookie carries an
	// AES-256-GCM-sealed TokenSet; verification uses its ID token.
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		if sessions == nil {
			return "", errInvalidSession
		}
		set, err := sessions.Open(cookie.Value)
		if err != nil {
			return "", err
		}
		return set.IDToken, nil
	}

	return "", nil
}
