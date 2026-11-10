package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/belLena81/devOpsDesk/internal/auth"
	"github.com/belLena81/devOpsDesk/internal/config"
	"github.com/belLena81/devOpsDesk/internal/db"
	"github.com/belLena81/devOpsDesk/internal/graph"
	"github.com/belLena81/devOpsDesk/internal/repository"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	authSvc := auth.NewService(repository.NewUserRepository(pool), cfg.JWTSecret, cfg.JWTTTL)

	gql := handler.New(graph.NewExecutableSchema(graph.Config{
		Resolvers: &graph.Resolver{Auth: authSvc, Log: log},
	}))
	gql.AddTransport(transport.Options{})
	gql.AddTransport(transport.GET{})
	gql.AddTransport(transport.POST{})
	gql.Use(extension.Introspection{})

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Handle("/query", auth.Middleware(authSvc)(gql))
	r.Handle("/playground", playground.Handler("DevOpsDesk", "/query"))

	if cfg.GitHubEnabled() {
		gh := auth.NewGitHubHandler(authSvc,
			auth.NewGitHubOAuth(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubRedirectURL),
			cfg.CookieSecure, cfg.OAuthSuccessRedirect, log)
		r.Get("/auth/github/login", gh.Login)
		r.Get("/auth/github/callback", gh.Callback)
	} else {
		log.Warn("GitHub sign-in disabled: GITHUB_CLIENT_ID not set")
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr, "playground", "/playground")
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
}
