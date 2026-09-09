package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	IssuerURL    string // e.g., "http://localhost:8080/realms/bouncer"
	ClientID     string // Client ID configured in IdP (Keycloak)
	ClientSecret string // Optional if using public client with PKCE
	RedirectURL  string // e.g., "http://localhost:8081/auth/callback"
}

type Authenticator struct {
	Provider     *oidc.Provider
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

// AdminClaims holds extracted Identity and Access claims from the ID/Access token.
type AdminClaims struct {
	Subject           string                `json:"sub"`
	Email             string                `json:"email"`
	PreferredUsername string                `json:"preferred_username"`
	ResourceAccess    map[string]ClientRole `json:"resource_access,omitempty"`
	RealmAccess       RealmRole             `json:"realm_access,omitempty"`
	Groups            []string              `json:"groups,omitempty"`
}

type RealmRole struct {
	Roles []string `json:"roles"`
}

type ClientRole struct {
	Roles []string `json:"roles"`
}

func NewAuthenticator(ctx context.Context, cfg Config) (*Authenticator, error) {

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover oidc provider: %w", err)
	}

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Force the client_id into the POST body
	oauthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Authenticator{
		Provider:     provider,
		OAuth2Config: oauthConfig,
		Verifier:     verifier,
	}, nil
}

// GeneratePKCE creates a high-entropy verifier and its corresponding SHA-256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("failed to read entropy for PKCE: %w", err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// GenerateState creates a cryptographically secure random string to prevent CSRF.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthCodeURL constructs the redirect URL with state, PKCE challenge, and S256 method.
func (a *Authenticator) AuthCodeURL(state, challenge string) string {
	return a.OAuth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange exchanges the authorization code and PKCE verifier for an OIDC token set.
func (a *Authenticator) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", verifier),
	}
	token, err := a.OAuth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	return token, nil
}

// VerifyIDToken parses and cryptographically validates the ID token signature and expiry.
func (a *Authenticator) VerifyIDToken(ctx context.Context, rawToken string) (*oidc.IDToken, *AdminClaims, error) {
	idToken, err := a.Verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify raw ID token: %w", err)
	}

	var claims AdminClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return idToken, &claims, nil
}

// HasRole checks whether the claims include the designated administrative role.
func (c *AdminClaims) HasRole(clientID, targetRole string) bool {
	// 1. Check Keycloak realm-level roles
	for _, r := range c.RealmAccess.Roles {
		if r == targetRole {
			return true
		}
	}

	// 2. Check client-specific roles
	if clientRoles, ok := c.ResourceAccess[clientID]; ok {
		for _, r := range clientRoles.Roles {
			if r == targetRole {
				return true
			}
		}
	}

	// 3. Check generic groups
	for _, g := range c.Groups {
		if g == targetRole {
			return true
		}
	}

	return false
}
