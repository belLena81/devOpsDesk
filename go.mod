module github.com/belLena81/devOpsDesk

go 1.26

require (
	github.com/golang-jwt/jwt/v5 v5.2.3
	github.com/google/uuid v1.6.0

	// Database
	github.com/jackc/pgx/v5 v5.5.5
	golang.org/x/crypto v0.17.0
)

require (
	// GraphQL
	github.com/99designs/gqlgen v0.17.45 // indirect

	// Docker
	github.com/docker/docker v25.0.5+incompatible // indirect

	// HTTP Router
	github.com/go-chi/chi/v5 v5.0.12 // indirect
	github.com/golang/mock v1.6.0 // indirect

	// WebSockets
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect

	// Metrics
	github.com/prometheus/client_golang v1.18.0 // indirect

	// Config
	github.com/spf13/viper v1.18.2 // indirect

	// Testing
	github.com/stretchr/testify v1.9.0 // indirect

	// Logging
	go.uber.org/zap v1.27.0 // indirect

	// Auth
	golang.org/x/oauth2 v0.18.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	k8s.io/api v0.29.4 // indirect
	k8s.io/apimachinery v0.29.4 // indirect

	// Kubernetes
	k8s.io/client-go v0.29.4 // indirect
)
