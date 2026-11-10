package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/belLena81/devOpsDesk/internal/domain"
)

const uniqueViolation = "23505"

const userColumns = `id, email, password_hash, github_id, github_login, created_at`

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID(), u.Email(), nullString(u.PasswordHash()), nullInt64(u.GitHubID()), nullString(u.GitHubLogin()), u.CreatedAt(),
	)
	return mapWriteError(err)
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
}

func (r *UserRepository) GetByGitHubID(ctx context.Context, githubID int64) (*domain.User, error) {
	return r.getOne(ctx, `SELECT `+userColumns+` FROM users WHERE github_id = $1`, githubID)
}

func (r *UserRepository) getOne(ctx context.Context, query string, arg any) (*domain.User, error) {
	var (
		id           uuid.UUID
		email        string
		passwordHash *string
		githubID     *int64
		githubLogin  *string
		createdAt    time.Time
	)
	err := r.db.QueryRow(ctx, query, arg).Scan(&id, &email, &passwordHash, &githubID, &githubLogin, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return domain.RestoreUser(id, email, deref(passwordHash), deref(githubID), deref(githubLogin), createdAt)
}

func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		switch pgErr.ConstraintName {
		case "users_email_key":
			return domain.ErrEmailTaken
		case "users_github_id_key":
			return domain.ErrGitHubIDTaken
		}
	}
	return err
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullInt64(n int64) *int64 {
	if n == 0 {
		return nil
	}
	return &n
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
