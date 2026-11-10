package domain

import (
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidID      = errors.New("invalid id")
	ErrInvalidEmail   = errors.New("invalid email")
	ErrMissingAuth    = errors.New("user must have a password or a linked GitHub account")
	ErrUserNotFound   = errors.New("user not found")
	ErrEmailTaken     = errors.New("email already registered")
	ErrGitHubIDTaken  = errors.New("github account already registered")
	ErrInvalidGitHub  = errors.New("invalid github account")
	ErrPasswordNotSet = errors.New("password not set")
)

// User is an account that can sign in with a password, GitHub, or both.
// Fields are unexported: build a User with NewPasswordUser / NewGitHubUser,
// or RestoreUser when loading from storage.
type User struct {
	id           uuid.UUID
	email        string
	passwordHash string // empty when the account has no password (GitHub-only)
	githubID     int64  // 0 when no GitHub account is linked
	githubLogin  string
	createdAt    time.Time
}

// NewPasswordUser creates an account that signs in with email and password.
func NewPasswordUser(id uuid.UUID, email, passwordHash string) (*User, error) {
	if passwordHash == "" {
		return nil, ErrPasswordNotSet
	}
	return newUser(id, email, passwordHash, 0, "")
}

// NewGitHubUser creates an account that signs in with GitHub.
func NewGitHubUser(id uuid.UUID, email string, githubID int64, githubLogin string) (*User, error) {
	if githubID <= 0 || githubLogin == "" {
		return nil, ErrInvalidGitHub
	}
	return newUser(id, email, "", githubID, githubLogin)
}

// RestoreUser rebuilds a User from persisted state. It applies the same
// invariants as the constructors so corrupt rows are not silently accepted.
func RestoreUser(id uuid.UUID, email, passwordHash string, githubID int64, githubLogin string, createdAt time.Time) (*User, error) {
	u, err := newUser(id, email, passwordHash, githubID, githubLogin)
	if err != nil {
		return nil, err
	}
	u.createdAt = createdAt.UTC()
	return u, nil
}

func newUser(id uuid.UUID, email, passwordHash string, githubID int64, githubLogin string) (*User, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidID
	}
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	if passwordHash == "" && githubID == 0 {
		return nil, ErrMissingAuth
	}
	return &User{
		id:           id,
		email:        normalized,
		passwordHash: passwordHash,
		githubID:     githubID,
		githubLogin:  githubLogin,
		// Microsecond precision matches what PostgreSQL stores.
		createdAt: time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

// NormalizeEmail trims and lowercases an email and checks it is a bare address.
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", ErrInvalidEmail
	}
	return email, nil
}

func (u *User) ID() uuid.UUID        { return u.id }
func (u *User) Email() string        { return u.email }
func (u *User) PasswordHash() string { return u.passwordHash }
func (u *User) HasPassword() bool    { return u.passwordHash != "" }
func (u *User) GitHubID() int64      { return u.githubID }
func (u *User) GitHubLogin() string  { return u.githubLogin }
func (u *User) CreatedAt() time.Time { return u.createdAt }
