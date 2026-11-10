package graph

//go:generate sh -c "cd ../.. && go tool gqlgen generate"

import (
	"context"
	"errors"
	"log/slog"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/belLena81/devOpsDesk/internal/auth"
	"github.com/belLena81/devOpsDesk/internal/domain"
	"github.com/belLena81/devOpsDesk/internal/graph/model"
)

// Resolver holds the dependencies resolvers need. Wired in cmd/server.
type Resolver struct {
	Auth *auth.Service
	Log  *slog.Logger
}

func toUser(u *domain.User) *model.User {
	out := &model.User{
		ID:          u.ID().String(),
		Email:       u.Email(),
		HasPassword: u.HasPassword(),
	}
	if login := u.GitHubLogin(); login != "" {
		out.GithubLogin = &login
	}
	return out
}

// publicErrors are safe to show to API clients as-is.
var publicErrors = []error{
	auth.ErrInvalidCredentials,
	auth.ErrWeakPassword,
	domain.ErrInvalidEmail,
	domain.ErrEmailTaken,
}

// clientError returns err unchanged if it is meant for clients, and otherwise
// logs it and returns a generic error so internals (SQL, etc.) don't leak.
func (r *Resolver) clientError(ctx context.Context, err error) error {
	for _, pub := range publicErrors {
		if errors.Is(err, pub) {
			return gqlerror.Errorf("%s", pub.Error())
		}
	}
	r.Log.ErrorContext(ctx, "resolver error", "err", err)
	return gqlerror.Errorf("internal server error")
}
