# My Blog API

A simple Go REST API for a blog, supporting PostgreSQL, CORS, authentication, and TipTap JSONB content.

## Environment
Copy `.env.example` to `.env` and set:
- `DATABASE_URL` — PostgreSQL connection string
- `AUTH_TOKEN` — Secret for protected routes
- `PORT` — Port to run the server (default: 8080)
- `CORS_ALLOWED_ORIGINS` — Comma-separated list of allowed origins


## Running
1. Install Go 1.20+ and PostgreSQL
2. `go mod tidy`
3. `go run .`

## License
MIT
