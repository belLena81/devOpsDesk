package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubProvider runs the GitHub side of the OAuth flow.
type GitHubProvider interface {
	// AuthCodeURL returns the GitHub consent URL for this state and PKCE verifier.
	AuthCodeURL(state, verifier string) string
	// Exchange trades the callback code for a token and fetches the profile.
	Exchange(ctx context.Context, code, verifier string) (GitHubProfile, error)
}

type GitHubOAuth struct {
	cfg     *oauth2.Config
	apiBase string
}

func NewGitHubOAuth(clientID, clientSecret, redirectURL string) *GitHubOAuth {
	return &GitHubOAuth{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     github.Endpoint,
			Scopes:       []string{"read:user", "user:email"},
		},
		apiBase: "https://api.github.com",
	}
}

func (g *GitHubOAuth) AuthCodeURL(state, verifier string) string {
	return g.cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (g *GitHubOAuth) Exchange(ctx context.Context, code, verifier string) (GitHubProfile, error) {
	token, err := g.cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return GitHubProfile{}, fmt.Errorf("exchange code: %w", err)
	}
	client := g.cfg.Client(ctx, token)

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := g.getJSON(ctx, client, "/user", &user); err != nil {
		return GitHubProfile{}, err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.getJSON(ctx, client, "/user/emails", &emails); err != nil {
		return GitHubProfile{}, err
	}

	profile := GitHubProfile{ID: user.ID, Login: user.Login}
	for _, e := range emails {
		if e.Primary && e.Verified {
			profile.Email = e.Email
			break
		}
	}
	return profile, nil
}

func (g *GitHubOAuth) getJSON(ctx context.Context, client *http.Client, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("github %s: status %d: %s", path, resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("github %s: decode: %w", path, err)
	}
	return nil
}
