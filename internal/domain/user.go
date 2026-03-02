package domain

import (
	"errors"

	"github.com/google/uuid"
)

type User struct {
	id       uuid.UUID
	email    string
	password string // hashed
}

func (u *User) Id() uuid.UUID {
	return u.id
}
func (u *User) Email() string {
	return u.email
}
func (u *User) Password() string {
	return u.password
}
func (u *User) SetPassword(password string) {
	u.password = password
}
func CreateUser(id uuid.UUID, email string, password string) (*User, error) {
	if id == uuid.Nil {
		return nil, errors.New("invalid id")
	}
	if email == "" || password == "" {
		return nil, errors.New("invalid email or password")
	}
	return &User{id: id, email: email, password: password}, nil
}
