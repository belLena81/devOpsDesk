package repository

import (
	"context"
	"errors"

	"github.com/belLena81/devOpsDesk/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `INSERT INTO users (id, email, password) VALUES ($1,$2,$3)`
	_, err := r.db.Exec(ctx, query, user.Id(), user.Email(), user.Password())
	return err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password FROM users WHERE email=$1`
	row := r.db.QueryRow(ctx, query, email)

	var u domain.User
	if err := row.Scan(u.Id(), u.Email(), u.Password()); err != nil {
		return nil, errors.New("user not found")
	}
	return &u, nil
}
