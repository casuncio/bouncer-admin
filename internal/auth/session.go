package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SessionCookieName is the browser session cookie that carries the sealed token set.
const SessionCookieName = "admin_session"

// errInvalidSession is the uniform error for every Open failure (tampering,
// wrong key, malformed input). Callers cannot distinguish failure reasons.
var errInvalidSession = errors.New("invalid session cookie")

// TokenSet is the plaintext payload sealed inside the session cookie. Only the
// ID token is verified by the middleware today; the access and refresh tokens
// are carried for future use (userinfo calls, refresh flows).
type TokenSet struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// SessionCodec seals and opens session cookie values using AES-256-GCM. The
// key is derived from the configured secret via SHA-256, so any non-empty
// secret is accepted. Sealed values are base64url(nonce ‖ ciphertext+tag) and
// are safe to store in a cookie.
type SessionCodec struct {
	aead cipher.AEAD
}

// NewSessionCodec returns a codec keyed by SHA-256(secret).
func NewSessionCodec(secret string) (*SessionCodec, error) {
	if secret == "" {
		return nil, errors.New("session secret must not be empty")
	}

	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &SessionCodec{aead: aead}, nil
}

// Seal encrypts and authenticates set, returning a cookie-safe string. Every
// call uses a fresh random nonce, so sealing the same set twice yields
// different values.
func (c *SessionCodec) Seal(set TokenSet) (string, error) {
	plaintext, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token set: %w", err)
	}
	return c.seal(plaintext)
}

// SealValue seals a single secret string — such as the PKCE verifier — into a
// cookie-safe value. It is the string counterpart of Seal for payloads that
// are not token sets.
func (c *SessionCodec) SealValue(value string) (string, error) {
	return c.seal([]byte(value))
}

// seal encrypts and authenticates plaintext, returning a cookie-safe string.
// Every call uses a fresh random nonce, so sealing the same plaintext twice
// yields different values.
func (c *SessionCodec) seal(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to read session nonce: %w", err)
	}

	// Passing nonce as dst prepends it to the ciphertext+tag.
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal. All failures — tampering, wrong key,
// or malformed input — return errInvalidSession so callers cannot distinguish
// failure reasons; the middleware reports them as an invalid token.
func (c *SessionCodec) Open(value string) (TokenSet, error) {
	var set TokenSet

	plaintext, err := c.open(value)
	if err != nil {
		return set, err
	}

	if err := json.Unmarshal(plaintext, &set); err != nil {
		return set, errInvalidSession
	}

	return set, nil
}

// OpenValue decrypts a value produced by SealValue. All failures return
// errInvalidSession, matching Open.
func (c *SessionCodec) OpenValue(value string) (string, error) {
	plaintext, err := c.open(value)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// open decrypts and authenticates a value produced by seal. All failures —
// tampering, wrong key, or malformed input — return errInvalidSession so
// callers cannot distinguish failure reasons.
func (c *SessionCodec) open(value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errInvalidSession
	}

	nonceSize := c.aead.NonceSize()
	if len(sealed) < nonceSize+c.aead.Overhead() {
		return nil, errInvalidSession
	}

	plaintext, err := c.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, errInvalidSession
	}

	return plaintext, nil
}
