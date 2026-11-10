package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/belLena81/devOpsDesk/internal/domain"
)

const testSecret = "test-secret-that-is-at-least-32-bytes!!"

// memStore is an in-memory UserStore that enforces the same uniqueness
// rules as the users table.
type memStore struct {
	mu    sync.Mutex
	users map[uuid.UUID]*domain.User
}

func newMemStore() *memStore { return &memStore{users: map[uuid.UUID]*domain.User{}} }

func (m *memStore) Create(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Email() == u.Email() {
			return domain.ErrEmailTaken
		}
		if u.GitHubID() != 0 && existing.GitHubID() == u.GitHubID() {
			return domain.ErrGitHubIDTaken
		}
	}
	m.users[u.ID()] = u
	return nil
}

func (m *memStore) find(match func(*domain.User) bool) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if match(u) {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *memStore) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.ID() == id })
}

func (m *memStore) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.Email() == email })
}

func (m *memStore) GetByGitHubID(_ context.Context, id int64) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.GitHubID() == id })
}

func newTestService() (*Service, *memStore) {
	store := newMemStore()
	return NewService(store, testSecret, time.Hour), store
}

func TestSignUpAndSignIn(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService()

	user, token, err := svc.SignUp(ctx, "  Alice@Example.com ", "correct-horse")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email())
	assert.True(t, user.HasPassword())
	assert.NotEqual(t, "correct-horse", user.PasswordHash())

	id, err := svc.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, user.ID(), id)

	signedIn, _, err := svc.SignIn(ctx, "ALICE@example.com", "correct-horse")
	require.NoError(t, err)
	assert.Equal(t, user.ID(), signedIn.ID())
}

func TestSignUpValidation(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService()

	_, _, err := svc.SignUp(ctx, "not-an-email", "correct-horse")
	assert.ErrorIs(t, err, domain.ErrInvalidEmail)

	_, _, err = svc.SignUp(ctx, "a@example.com", "short")
	assert.ErrorIs(t, err, ErrWeakPassword)

	_, _, err = svc.SignUp(ctx, "a@example.com", string(make([]byte, MaxPasswordLength+1)))
	assert.ErrorIs(t, err, ErrWeakPassword)

	_, _, err = svc.SignUp(ctx, "a@example.com", "correct-horse")
	require.NoError(t, err)
	_, _, err = svc.SignUp(ctx, "A@example.com", "another-password")
	assert.ErrorIs(t, err, domain.ErrEmailTaken)
}

func TestSignInFailures(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService()
	_, _, err := svc.SignUp(ctx, "bob@example.com", "correct-horse")
	require.NoError(t, err)
	_, _, err = svc.SignInWithGitHub(ctx, GitHubProfile{ID: 7, Login: "carol", Email: "carol@example.com"})
	require.NoError(t, err)

	cases := map[string]struct{ email, password string }{
		"wrong password":       {"bob@example.com", "wrong-password"},
		"unknown email":        {"nobody@example.com", "correct-horse"},
		"malformed email":      {"bob", "correct-horse"},
		"github-only account":  {"carol@example.com", "anything-at-all"},
		"github-only no input": {"carol@example.com", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := svc.SignIn(ctx, tc.email, tc.password)
			assert.ErrorIs(t, err, ErrInvalidCredentials)
		})
	}
}

func TestSignInWithGitHub(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService()
	profile := GitHubProfile{ID: 42, Login: "octocat", Email: "Octo@Example.com"}

	first, token, err := svc.SignInWithGitHub(ctx, profile)
	require.NoError(t, err)
	assert.Equal(t, "octo@example.com", first.Email())
	assert.Equal(t, "octocat", first.GitHubLogin())
	assert.False(t, first.HasPassword())
	_, err = svc.ParseToken(token)
	require.NoError(t, err)

	// Second sign-in finds the same account by GitHub ID, even if the
	// GitHub email changed.
	profile.Email = "new@example.com"
	second, _, err := svc.SignInWithGitHub(ctx, profile)
	require.NoError(t, err)
	assert.Equal(t, first.ID(), second.ID())
	assert.Len(t, store.users, 1)
}

func TestSignInWithGitHubDoesNotTakeOverPasswordAccount(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService()
	_, _, err := svc.SignUp(ctx, "dave@example.com", "correct-horse")
	require.NoError(t, err)

	_, _, err = svc.SignInWithGitHub(ctx, GitHubProfile{ID: 1, Login: "dave", Email: "dave@example.com"})
	assert.ErrorIs(t, err, ErrAccountExists)

	// And a password sign-up can't claim a GitHub user's email.
	_, _, err = svc.SignInWithGitHub(ctx, GitHubProfile{ID: 2, Login: "erin", Email: "erin@example.com"})
	require.NoError(t, err)
	_, _, err = svc.SignUp(ctx, "erin@example.com", "correct-horse")
	assert.ErrorIs(t, err, domain.ErrEmailTaken)
}

func TestSignInWithGitHubRequiresVerifiedEmail(t *testing.T) {
	svc, _ := newTestService()
	_, _, err := svc.SignInWithGitHub(context.Background(), GitHubProfile{ID: 3, Login: "frank"})
	assert.ErrorIs(t, err, ErrGitHubEmailMissing)
}

func TestParseTokenRejectsBadTokens(t *testing.T) {
	svc, _ := newTestService()
	sub := uuid.New().String()

	sign := func(method jwt.SigningMethod, key any, claims jwt.RegisteredClaims) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		require.NoError(t, err)
		return s
	}
	valid := jwt.RegisteredClaims{Subject: sub, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}

	cases := map[string]string{
		"garbage":      "not.a.token",
		"wrong secret": sign(jwt.SigningMethodHS256, []byte("some-other-secret-of-32-bytes-or-more"), valid),
		"alg none":     sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, valid),
		"wrong alg":    sign(jwt.SigningMethodHS512, []byte(testSecret), valid),
		"expired": sign(jwt.SigningMethodHS256, []byte(testSecret), jwt.RegisteredClaims{
			Subject: sub, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		}),
		"no expiry":   sign(jwt.SigningMethodHS256, []byte(testSecret), jwt.RegisteredClaims{Subject: sub}),
		"bad subject": sign(jwt.SigningMethodHS256, []byte(testSecret), jwt.RegisteredClaims{Subject: "x", ExpiresAt: valid.ExpiresAt}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.ParseToken(token)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}

	id, err := svc.ParseToken(sign(jwt.SigningMethodHS256, []byte(testSecret), valid))
	require.NoError(t, err)
	assert.Equal(t, sub, id.String())
}
