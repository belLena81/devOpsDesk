📖 Core Overview
DevOpsDesk was created to bridge the gap between backend development and infrastructure management. Instead of manual terminal-based deployments, this tool provides a safe, auditable, and graphical way to:

Visualize exactly what is running in Staging vs. Production.

Control the deployment lifecycle (Deploy, Stop, Restart).

Recover instantly from bad releases with a "One-Click Rollback" button.

Stream live container logs directly to the browser via GraphQL Subscriptions.

🔐 Authentication & Identity
GitHub OAuth Integration: Secure login using existing developer accounts.

Organization Guardrails: Restrict access to specific GitHub Organizations or Teams.

Session Management: Secure JWT-based authentication for all API requests.

🖥️ Environment Monitoring
Live Discovery: Auto-detects running containers using the official Docker SDK.

Health Indicators: Real-time "Up/Down" status, CPU usage, and Memory consumption.

Resource List: View container IDs, image tags, and exposed ports in a unified table.

🏗️ Deployment & Persistence
Deployment Trigger: Manually pull and restart containers with specific image tags.

History Database: A GORM-powered audit log tracking:

Who triggered the deployment.

Which image version was used.

When the event started and finished.

Persistent State: PostgreSQL storage for deployment logs and environment metadata.

📡 GraphQL API Layer
Unified Schema: A type-safe API (via gqlgen) for fetching environment data.

Optimized Queries: The frontend requests only the specific fields needed, reducing bandwidth.

🛠️ Technical Stack
Language: Go (Golang)

API: GraphQL via gqlgen

Orchestration: Docker SDK for Go

Database: PostgreSQL with GORM

Auth: GitHub OAuth2 (golang.org/x/oauth2)

📂 Project Structure
Plaintext
/cmd/server/        # App entry point
/internal/
/auth/            # OAuth2 & Session logic
/deploy/          # Docker SDK orchestration
/graph/           # GraphQL Schema & Resolvers
/models/          # GORM database structs
/pkg/               # Reusable utility functions
🚦 Getting Started
Clone the repo: git clone https://github.com/belLena81/devOpsDesk.git

Setup Env: Copy .env.example to .env and add your GITHUB_CLIENT_ID.

Run: go run cmd/server/main.go

Access: Open http://localhost:8080/playground to test the GraphQL API.