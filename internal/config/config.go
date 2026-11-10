// Package config loads settings from environment variables, falling back to
// a .env file in the working directory if one exists.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string

	JWTSecret string
	JWTTTL    time.Duration

	// GitHub OAuth is enabled only when GitHubClientID is set.
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string
	// OAuthSuccessRedirect, if set, is where the browser is sent with
	// "#token=..." after GitHub sign-in; otherwise the callback returns JSON.
	OAuthSuccessRedirect string
	// CookieSecure marks OAuth state cookies Secure. Enable behind HTTPS.
	CookieSecure bool
}

func (c Config) GitHubEnabled() bool { return c.GitHubClientID != "" }

const minJWTSecretLength = 32

func Load() (Config, error) {
	v := viper.New()
	v.SetDefault("HTTP_ADDR", ":8080")
	v.SetDefault("JWT_TTL", "24h")
	v.SetDefault("GITHUB_REDIRECT_URL", "http://localhost:8080/auth/github/callback")
	v.SetDefault("COOKIE_SECURE", false)
	for _, key := range []string{
		"DATABASE_URL", "JWT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "OAUTH_SUCCESS_REDIRECT",
	} {
		v.SetDefault(key, "")
	}
	v.AutomaticEnv() // real environment variables win over .env

	if _, err := os.Stat(".env"); err == nil {
		v.SetConfigFile(".env")
		v.SetConfigType("env")
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read .env: %w", err)
		}
	}

	cfg := Config{
		HTTPAddr:             v.GetString("HTTP_ADDR"),
		DatabaseURL:          v.GetString("DATABASE_URL"),
		JWTSecret:            v.GetString("JWT_SECRET"),
		JWTTTL:               v.GetDuration("JWT_TTL"),
		GitHubClientID:       v.GetString("GITHUB_CLIENT_ID"),
		GitHubClientSecret:   v.GetString("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURL:    v.GetString("GITHUB_REDIRECT_URL"),
		OAuthSuccessRedirect: v.GetString("OAUTH_SUCCESS_REDIRECT"),
		CookieSecure:         v.GetBool("COOKIE_SECURE"),
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(c.JWTSecret) < minJWTSecretLength {
		errs = append(errs, fmt.Errorf("JWT_SECRET must be at least %d characters", minJWTSecretLength))
	}
	if c.JWTTTL <= 0 {
		errs = append(errs, errors.New("JWT_TTL must be a positive duration, e.g. 24h"))
	}
	if c.GitHubEnabled() && c.GitHubClientSecret == "" {
		errs = append(errs, errors.New("GITHUB_CLIENT_SECRET is required when GITHUB_CLIENT_ID is set"))
	}
	return errors.Join(errs...)
}
