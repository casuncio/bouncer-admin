package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/casuncio/bouncer-admin/internal/api"
	"github.com/casuncio/bouncer-admin/internal/auth"
)

func main() {
	ctx := context.Background()

	// Initalizing structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	authConfig := auth.Config{
		IssuerURL:    "http://127.0.0.1:5556/dex",
		ClientID:     "bouncer-admin-gui",
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/auth/callback",
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
