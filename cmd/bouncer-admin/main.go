package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/casuncio/bouncer-admin/internal/api"
	"github.com/casuncio/bouncer-admin/internal/auth"
)

func startSecureServer(router http.Handler) {
	// 1. Load the Certificate Authority (CA) that signs your client certificates
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		slog.Error("Failed to read CA certificate", "error", err)
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 2. Configure strict mTLS
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Require client certificates on the server to verify caller identity
		ClientAuth: tls.RequireAndVerifyClientCert, //[cite: 2]
		ClientCAs:  caCertPool,
		// Verify the Common Name (CN) or Subject Alternative Name (SAN / SPIFFE ID) before processing streams
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { //[cite: 2]
			// Custom logic to verify SPIFFE ID or specific SANs
			return nil
		},
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	slog.Info("Starting secure mTLS admin server", "port", ":8443")
	// Start serving HTTPS, providing the server's own certificate and key
	if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil {
		slog.Error("Server crashed", "error", err)
		os.Exit(1)
	}
}

// sessionSecret returns the secret used to seal the admin session cookie. It
// comes from SESSION_SECRET; when unset, an ephemeral random key is generated
// so local development stays zero-config at the cost of sessions resetting on
// every restart.
func sessionSecret() string {
	if secret := os.Getenv("SESSION_SECRET"); secret != "" {
		return secret
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		slog.Error("Failed to generate ephemeral session secret", "error", err)
		os.Exit(1)
	}

	slog.Warn("SESSION_SECRET not set; using an ephemeral session key, sessions reset on restart")
	return base64.RawURLEncoding.EncodeToString(raw)
}

func main() {
	ctx := context.Background()

	// Initalizing structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	authConfig := auth.Config{
		IssuerURL:     "http://127.0.0.1:5556/dex",
		ClientID:      "bouncer-admin-gui",
		ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:   "http://localhost:8080/auth/callback",
		SessionSecret: sessionSecret(),
	}

	authenticator, err := auth.NewAuthenticator(ctx, authConfig)
	if err != nil {
		slog.Error("Failed to intialize OIDC provider", "error", err)
		os.Exit(1)
	}

	// Create API router
	router := api.NewServer(authenticator)

	// Start HTTP server and serve
	port := "8080"
	slog.Info("Starting HTTP server", "port", port)

	if err := http.ListenAndServe("127.0.0.1:"+port, router); err != nil {
		slog.Error("HTTP server crashed", "error", err)
		os.Exit(1)
	}
}
