package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/belLena81/devOpsDesk/internal/domain"
	"github.com/belLena81/devOpsDesk/internal/repository"
)

type Service struct {
	repo      *repository.UserRepository
	jwtSecret []byte
}

func NewService(repo *repository.UserRepository, secret string) *Service {
	return &Service{
		repo:      repo,
		jwtSecret: []byte(secret),
	}
}

func (s *Service) SignUp(ctx context.Context, email, password string) (*domain.User, string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	user, err := domain.CreateUser(uuid.New(), email, string(hashed))
	if err != nil {
		return nil, "", err
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, "", err
	}

	token, err := s.generateToken(user.Id())
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *Service) SignIn(ctx context.Context, email, password string) (*domain.User, string, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password()), []byte(password)); err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	token, err := s.generateToken(user.Id())
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *Service) generateToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.jwtSecret)
}
