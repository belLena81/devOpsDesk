package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type ctxKey struct{}

// Middleware reads an optional "Authorization: Bearer <jwt>" header and puts
// the user ID in the request context. Requests without the header pass
// through unauthenticated; requests with an invalid token get 401.
func Middleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				next.ServeHTTP(w, r)
				return
			}
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok {
				writeJSONError(w, http.StatusUnauthorized, "authorization header must be 'Bearer <token>'")
				return
			}
			userID, err := svc.ParseToken(strings.TrimSpace(token))
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, userID)))
		})
	}
}

// UserIDFromContext returns the authenticated user ID, if any.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(ctxKey{}).(uuid.UUID)
	return id, ok
}
