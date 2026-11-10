package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeGitHub struct {
	profile      GitHubProfile
	gotCode      string
	gotVerifier  string
	exchangeErr  error
	lastState    string
	lastVerifier string
}

func (f *fakeGitHub) AuthCodeURL(state, verifier string) string {
	f.lastState, f.lastVerifier = state, verifier
	return "https://github.example/authorize?state=" + url.QueryEscape(state)
}

func (f *fakeGitHub) Exchange(_ context.Context, code, verifier string) (GitHubProfile, error) {
	f.gotCode, f.gotVerifier = code, verifier
	return f.profile, f.exchangeErr
}

func newTestHandler(t *testing.T, successRedirect string) (*GitHubHandler, *fakeGitHub, *Service) {
	t.Helper()
	svc, _ := newTestService()
	gh := &fakeGitHub{profile: GitHubProfile{ID: 99, Login: "octocat", Email: "octo@example.com"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewGitHubHandler(svc, gh, false, successRedirect, log), gh, svc
}

// login runs /auth/github/login and returns the cookies it set.
func login(t *testing.T, h *GitHubHandler) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/auth/github/login", nil))
	require.Equal(t, http.StatusFound, rec.Code)
	return rec.Result().Cookies()
}

func callback(h *GitHubHandler, query string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/github/callback?"+query, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec
}

func TestGitHubCallbackSuccessJSON(t *testing.T) {
	h, gh, svc := newTestHandler(t, "")
	cookies := login(t, h)

	rec := callback(h, "code=abc&state="+url.QueryEscape(gh.lastState), cookies)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "abc", gh.gotCode)
	assert.Equal(t, gh.lastVerifier, gh.gotVerifier, "PKCE verifier from cookie is passed to the exchange")

	var body struct {
		Token string `json:"token"`
		User  struct {
			Email       string `json:"email"`
			GitHubLogin string `json:"githubLogin"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "octo@example.com", body.User.Email)
	assert.Equal(t, "octocat", body.User.GitHubLogin)
	_, err := svc.ParseToken(body.Token)
	assert.NoError(t, err)

	for _, c := range rec.Result().Cookies() {
		assert.Equal(t, -1, c.MaxAge, "cookie %s should be cleared", c.Name)
	}
}

func TestGitHubCallbackSuccessRedirect(t *testing.T) {
	h, gh, _ := newTestHandler(t, "http://localhost:3000/auth/done")
	cookies := login(t, h)

	rec := callback(h, "code=abc&state="+url.QueryEscape(gh.lastState), cookies)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Regexp(t, `^http://localhost:3000/auth/done#token=.+`, rec.Header().Get("Location"))
}

func TestGitHubCallbackRejectsBadState(t *testing.T) {
	h, gh, _ := newTestHandler(t, "")
	cookies := login(t, h)

	cases := map[string]struct {
		query   string
		cookies []*http.Cookie
	}{
		"state mismatch": {"code=abc&state=forged", cookies},
		"missing state":  {"code=abc", cookies},
		"no cookies":     {"code=abc&state=" + url.QueryEscape(gh.lastState), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := callback(h, tc.query, tc.cookies)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
	assert.Empty(t, gh.gotCode, "code must not be exchanged when state is invalid")
}

func TestGitHubCallbackEmailBelongsToPasswordAccount(t *testing.T) {
	h, gh, svc := newTestHandler(t, "")
	_, _, err := svc.SignUp(context.Background(), "octo@example.com", "correct-horse")
	require.NoError(t, err)
	cookies := login(t, h)

	rec := callback(h, "code=abc&state="+url.QueryEscape(gh.lastState), cookies)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "sign in with your password")
}

func TestMiddleware(t *testing.T) {
	svc, _ := newTestService()
	_, token, err := svc.SignUp(context.Background(), "mw@example.com", "correct-horse")
	require.NoError(t, err)

	var gotUser bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotUser = UserIDFromContext(r.Context())
	})
	mw := Middleware(svc)(next)

	do := func(header string) int {
		gotUser = false
		req := httptest.NewRequest(http.MethodPost, "/query", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		return rec.Code
	}

	assert.Equal(t, http.StatusOK, do(""))
	assert.False(t, gotUser)

	assert.Equal(t, http.StatusOK, do("Bearer "+token))
	assert.True(t, gotUser)

	assert.Equal(t, http.StatusUnauthorized, do("Bearer nope"))
	assert.Equal(t, http.StatusUnauthorized, do("Basic abc"))
}
