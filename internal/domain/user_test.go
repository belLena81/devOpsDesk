package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Alice@Example.COM ")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", got)

	for _, bad := range []string{"", "alice", "Alice <alice@example.com>", "a@b@c"} {
		_, err := NormalizeEmail(bad)
		assert.ErrorIs(t, err, ErrInvalidEmail, bad)
	}
}

func TestConstructorsEnforceInvariants(t *testing.T) {
	id := uuid.New()

	_, err := NewPasswordUser(uuid.Nil, "a@example.com", "hash")
	assert.ErrorIs(t, err, ErrInvalidID)

	_, err = NewPasswordUser(id, "a@example.com", "")
	assert.ErrorIs(t, err, ErrPasswordNotSet)

	_, err = NewGitHubUser(id, "a@example.com", 0, "octo")
	assert.ErrorIs(t, err, ErrInvalidGitHub)

	_, err = RestoreUser(id, "a@example.com", "", 0, "", time.Now())
	assert.ErrorIs(t, err, ErrMissingAuth)

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	u, err := RestoreUser(id, "a@example.com", "hash", 5, "octo", created)
	require.NoError(t, err)
	assert.True(t, u.HasPassword())
	assert.Equal(t, int64(5), u.GitHubID())
	assert.Equal(t, created, u.CreatedAt())
}
