package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/belLena81/devOpsDesk/internal/domain"
)

const (
	MinPasswordLength = 8
	MaxPasswordLength = 72 // bcrypt ignores bytes beyond 72
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrWeakPassword       = fmt.Errorf("password must be %d-%d bytes long", MinPasswordLength, MaxPasswordLength)
	// ErrAccountExists is returned when a GitHub sign-in uses an email that
	// already belongs to a password account. Accounts are not merged
	// automatically: sign-up does not verify email ownership, so auto-linking
	// would let someone pre-register a victim's email and share their account.
	ErrAccountExists = errors.New("an account with this email already exists; sign in with your password")
	// ErrGitHubEmailMissing is returned when the GitHub account has no
	// verified primary email.
	ErrGitHubEmailMissing = errors.New("github account has no verified primary email")
)

// UserStore is the persistence the auth service needs.
// *repository.UserRepository implements it.
type UserStore interface {
	Create(ctx context.Context, u *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByGitHubID(ctx context.Context, githubID int64) (*domain.User, error)
}

// GitHubProfile is the identity returned by GitHub after OAuth.
type GitHubProfile struct {
	ID    int64
	Login string
	Email string // verified primary email; empty if none
}

type Service struct {
	users     UserStore
	jwtSecret []byte
	tokenTTL  time.Duration
	now       func() time.Time
	// dummyHash is compared against when a user is not found, so that
	// sign-in takes similar time whether or not the email exists.
	dummyHash []byte
}

func NewService(users UserStore, jwtSecret string, tokenTTL time.Duration) *Service {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	return &Service{
		users:     users,
		jwtSecret: []byte(jwtSecret),
		tokenTTL:  tokenTTL,
		now:       time.Now,
		dummyHash: dummy,
	}
}

// SignUp creates an email/password account and returns it with a token.
func (s *Service) SignUp(ctx context.Context, email, password string) (*domain.User, string, error) {
	if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
		return nil, "", ErrWeakPassword
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash password: %w", err)
	}

	user, err := domain.NewPasswordUser(uuid.New(), email, string(hashed))
	if err != nil {
		return nil, "", err
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, "", err
	}
	return s.withToken(user)
}

// SignIn checks an email/password pair and returns the user with a token.
func (s *Service) SignIn(ctx context.Context, email, password string) (*domain.User, string, error) {
	normalized, err := domain.NormalizeEmail(email)
	if err != nil {
		return nil, "", ErrInvalidCredentials
	}

	user, err := s.users.GetByEmail(ctx, normalized)
	if errors.Is(err, domain.ErrUserNotFound) {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return nil, "", ErrInvalidCredentials
	}
	if err != nil {
		return nil, "", err
	}
	if !user.HasPassword() {
		// GitHub-only account.
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return nil, "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash()), []byte(password)); err != nil {
		return nil, "", ErrInvalidCredentials
	}
	return s.withToken(user)
}

// SignInWithGitHub signs in the account linked to this GitHub user, creating
// a new account on first sign-in.
func (s *Service) SignInWithGitHub(ctx context.Context, p GitHubProfile) (*domain.User, string, error) {
	user, err := s.users.GetByGitHubID(ctx, p.ID)
	if err == nil {
		return s.withToken(user)
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, "", err
	}

	if p.Email == "" {
		return nil, "", ErrGitHubEmailMissing
	}
	user, err = domain.NewGitHubUser(uuid.New(), p.Email, p.ID, p.Login)
	if err != nil {
		return nil, "", err
	}
	switch err := s.users.Create(ctx, user); {
	case errors.Is(err, domain.ErrEmailTaken):
		return nil, "", ErrAccountExists
	case errors.Is(err, domain.ErrGitHubIDTaken):
		// Lost a race with a concurrent first sign-in of the same account.
		existing, err := s.users.GetByGitHubID(ctx, p.ID)
		if err != nil {
			return nil, "", err
		}
		return s.withToken(existing)
	case err != nil:
		return nil, "", err
	}
	return s.withToken(user)
}

// UserByID loads a user, e.g. the one identified by a token.
func (s *Service) UserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

// ParseToken validates a token issued by this service and returns its user ID.
func (s *Service) ParseToken(tokenString string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(tokenString, &claims,
		func(*jwt.Token) (any, error) { return s.jwtSecret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	return id, nil
}

func (s *Service) withToken(user *domain.User) (*domain.User, string, error) {
	now := s.now()
	claims := jwt.RegisteredClaims{
		Subject:   user.ID().String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
	if err != nil {
		return nil, "", fmt.Errorf("sign token: %w", err)
	}
	return user, token, nil
}
