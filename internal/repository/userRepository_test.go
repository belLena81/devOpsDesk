package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/belLena81/devOpsDesk/internal/db"
	"github.com/belLena81/devOpsDesk/internal/domain"
)

// Integration tests: set TEST_DATABASE_URL to a disposable database, e.g.
//
//	TEST_DATABASE_URL=postgres://devopsdesk:devopsdesk@localhost:5432/devopsdesk_test?sslmode=disable
//
// The users table is truncated before each test.
func newTestRepo(t *testing.T) *UserRepository {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, url)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, db.Migrate(ctx, pool))
	require.NoError(t, db.Migrate(ctx, pool), "migrations must be idempotent")
	truncate(t, pool)
	return NewUserRepository(pool)
}

func truncate(t *testing.T, pool *pgxpool.Pool) {
	_, err := pool.Exec(context.Background(), `TRUNCATE users`)
	require.NoError(t, err)
}

func TestCreateAndGetPasswordUser(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	u, err := domain.NewPasswordUser(uuid.New(), "pw@example.com", "hash")
	require.NoError(t, err)
	require.NoError(t, repo.Create(ctx, u))

	for name, get := range map[string]func() (*domain.User, error){
		"by email": func() (*domain.User, error) { return repo.GetByEmail(ctx, "pw@example.com") },
		"by id":    func() (*domain.User, error) { return repo.GetByID(ctx, u.ID()) },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := get()
			require.NoError(t, err)
			assert.Equal(t, u.ID(), got.ID())
			assert.Equal(t, "pw@example.com", got.Email())
			assert.Equal(t, "hash", got.PasswordHash())
			assert.Zero(t, got.GitHubID())
			assert.Empty(t, got.GitHubLogin())
			assert.WithinDuration(t, u.CreatedAt(), got.CreatedAt(), 0)
		})
	}
}

func TestCreateAndGetGitHubUser(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	u, err := domain.NewGitHubUser(uuid.New(), "gh@example.com", 4242, "octocat")
	require.NoError(t, err)
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByGitHubID(ctx, 4242)
	require.NoError(t, err)
	assert.Equal(t, u.ID(), got.ID())
	assert.False(t, got.HasPassword())
	assert.Equal(t, "octocat", got.GitHubLogin())
}

func TestUniqueConstraintsMapToDomainErrors(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	gh, err := domain.NewGitHubUser(uuid.New(), "one@example.com", 1, "one")
	require.NoError(t, err)
	require.NoError(t, repo.Create(ctx, gh))

	sameEmail, err := domain.NewPasswordUser(uuid.New(), "one@example.com", "hash")
	require.NoError(t, err)
	assert.ErrorIs(t, repo.Create(ctx, sameEmail), domain.ErrEmailTaken)

	sameGitHub, err := domain.NewGitHubUser(uuid.New(), "two@example.com", 1, "one")
	require.NoError(t, err)
	assert.ErrorIs(t, repo.Create(ctx, sameGitHub), domain.ErrGitHubIDTaken)
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.GetByEmail(ctx, "missing@example.com")
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
	_, err = repo.GetByID(ctx, uuid.New())
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
	_, err = repo.GetByGitHubID(ctx, 123)
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}
