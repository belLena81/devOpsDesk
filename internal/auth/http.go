package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	stateCookie    = "gh_oauth_state"
	verifierCookie = "gh_oauth_verifier"
	cookiePath     = "/auth/github"
	cookieMaxAge   = 10 * time.Minute
)

// GitHubHandler serves GET /auth/github/login and GET /auth/github/callback.
type GitHubHandler struct {
	svc           *Service
	provider      GitHubProvider
	secureCookies bool
	// successRedirect, if set, receives the token as "#token=..." after
	// sign-in (for a browser frontend). Otherwise the callback returns JSON.
	successRedirect string
	log             *slog.Logger
}

func NewGitHubHandler(svc *Service, provider GitHubProvider, secureCookies bool, successRedirect string, log *slog.Logger) *GitHubHandler {
	return &GitHubHandler{svc: svc, provider: provider, secureCookies: secureCookies, successRedirect: successRedirect, log: log}
}

func (h *GitHubHandler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		h.log.Error("generate oauth state", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()

	h.setCookie(w, stateCookie, state, cookieMaxAge)
	h.setCookie(w, verifierCookie, verifier, cookieMaxAge)
	http.Redirect(w, r, h.provider.AuthCodeURL(state, verifier), http.StatusFound)
}

func (h *GitHubHandler) Callback(w http.ResponseWriter, r *http.Request) {
	stateC, errS := r.Cookie(stateCookie)
	verifierC, errV := r.Cookie(verifierCookie)
	h.clearCookie(w, stateCookie)
	h.clearCookie(w, verifierCookie)

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		writeJSONError(w, http.StatusUnauthorized, "github sign-in failed: "+e)
		return
	}
	if errS != nil || errV != nil || q.Get("state") == "" ||
		subtle.ConstantTimeCompare([]byte(stateC.Value), []byte(q.Get("state"))) != 1 {
		writeJSONError(w, http.StatusBadRequest, "invalid oauth state; start sign-in again")
		return
	}
	code := q.Get("code")
	if code == "" {
		writeJSONError(w, http.StatusBadRequest, "missing code")
		return
	}

	profile, err := h.provider.Exchange(r.Context(), code, verifierC.Value)
	if err != nil {
		h.log.Error("github exchange", "err", err)
		writeJSONError(w, http.StatusBadGateway, "could not complete github sign-in")
		return
	}

	user, token, err := h.svc.SignInWithGitHub(r.Context(), profile)
	switch {
	case errors.Is(err, ErrAccountExists), errors.Is(err, ErrGitHubEmailMissing):
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		h.log.Error("github sign-in", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if h.successRedirect != "" {
		http.Redirect(w, r, h.successRedirect+"#token="+url.QueryEscape(token), http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  map[string]any{"id": user.ID(), "email": user.Email(), "githubLogin": user.GitHubLogin()},
	})
}

func (h *GitHubHandler) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	h.writeCookie(w, name, value, int(maxAge.Seconds()))
}

// clearCookie deletes a cookie (MaxAge < 0 sends "Max-Age=0").
func (h *GitHubHandler) clearCookie(w http.ResponseWriter, name string) {
	h.writeCookie(w, name, "", -1)
}

func (h *GitHubHandler) writeCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
