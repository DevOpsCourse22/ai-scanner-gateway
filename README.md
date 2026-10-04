# AI Scan Repos gateway

The gateway is the control plane for the AI Scan Repos platform: it receives
GitHub webhooks, verifies repository access, connects a browser session to a
GitHub identity, and starts review jobs in the backend API without doing the
actual scanning itself.

This project follows the same overall product idea as the other AI Scan repos: a full repository review is run with authoritative, deterministic
security scanners such as Semgrep, Gitleaks and Trivy, while optional AI
analysis adds explanation, prioritization and remediation guidance. The gateway
is where GitHub events, login flow, review triggers and owner-aware history are
managed; it does not clone repositories or interpret scanner results.

## What this repo does

- Accepts GitHub webhook events and validates the HMAC signature.
- Extracts repository, branch and changed-file metadata from push and manual
  trigger requests.
- Starts a review through the backend `review-api` service.
- Tracks trigger-to-review relationships in its own database.
- Exposes an authenticated user flow with GitHub OAuth and session cookies.
- Protects deeper review modes so only authorized users can start them.
- Forwards status and report requests to the backend while keeping backend as
  the single source of truth for review execution.

```text
GitHub / browser
      │
      ▼
AI Scan Repos gateway
      │  verify webhook / auth / repo access
      ▼
backend review-api
      │  runs review pipeline
      ▼
deterministic scanners + AI enrichment
      ▼
report + status + resume support
```

This gateway is the "front door" of the platform: it owns user identity,
review orchestration and event ingestion, while the backend owns the actual
review job lifecycle.

## GitHub webhook + trigger flow

```text
GitHub ──HTTPS──▶ POST /webhook
                     │  validate HMAC-SHA256 signature
                     │  extract repo_url, branch, changed files
                     ▼
            review_client.start_review() ──▶ backend: POST /api/v1/reviews
                     │
                     ▼
             triggers table (SQLite/Postgres)
             {trigger_id -> review_id}
```

`GET /reviews/{trigger_id}` and `.../report` look up the stored review id and
proxy to the backend's status/report endpoints. The backend remains the single
source of truth for running review state, checkpoints, and final reports.

`POST /reviews` is the same review start path, but invoked manually instead of
by a webhook. That is the API used by the UI and by local testing.

## GitHub OAuth (login)

```text
GET /auth/github/login  ──▶ redirect to GitHub consent screen
GitHub ──▶ GET /auth/github/callback?code=...&state=...
            │  verify state matches the cookie
            │  exchange code for a token
            │  fetch GitHub user identity
            ▼
      auth_sessions table ──▶ browser receives HttpOnly session_id cookie
            ▼
      redirect to GATEWAY_FRONTEND_URL (the frontend app)
```

The browser never gets the raw GitHub access token. Only an opaque
`session_id` is stored in an `HttpOnly` cookie. Sessions expire after
`GATEWAY_SESSION_TTL_SECONDS`, and the gateway checks repository permission
before allowing a deep review to start.

**Deep mode gate:** `quick` and `brief` reviews stay open to anonymous callers,
while `deep` requires a signed-in user and repo read access. This matches the
platform's security model: the deterministic scan remains authoritative, and AI
is used as an added layer rather than a bypass around authorization controls.

## Quick start

```bash
# from this repository root
pip install -e ".[dev]"
cp .env.example .env
# edit .env: add the following variable
# GITHUB_WEBHOOK_SECRET, 
# GITHUB_OAUTH_CLIENT_ID,
# GITHUB_OAUTH_CLIENT_SECRET, 
# REVIEW_API_BASE_URL, and any required values
python -m review_gateway.app
```

`.env` is gitignored — never commit the filled-in copy. Environment variables
are loaded automatically via `python-dotenv`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | *(empty = refuses everything)* | HMAC secret configured on the GitHub webhook |
| `REVIEW_API_BASE_URL` | `http://localhost:8000` | Where the backend review API is listening |
| `REVIEW_API_KEY` | *(empty)* | Sent as `X-API-Key` if the backend requires one |
| `GATEWAY_DATABASE_URL` | `sqlite:///./gateway.db` | SQLAlchemy URL; point at Postgres in deployment |
| `GATEWAY_DEFAULT_MODE` | `brief` | Default review mode passed to the backend |
| `GITHUB_OAUTH_CLIENT_ID` | *(empty)* | GitHub OAuth App client id |
| `GITHUB_OAUTH_CLIENT_SECRET` | *(empty)* | GitHub OAuth App client secret |
| `GITHUB_OAUTH_REDIRECT_URI` | `http://localhost:8080/auth/github/callback` | Must match the OAuth App callback exactly |
| `GATEWAY_SESSION_TTL_SECONDS` | `28800` (8h) | Session lifetime before re-auth is required |
| `GATEWAY_COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `GATEWAY_CORS_ORIGINS` | `http://localhost:5173` | Allowed frontend origins |
| `GATEWAY_FRONTEND_URL` | `http://localhost:5173` | Where successful OAuth redirects back to the app |
| `GATEWAY_ADMINS` | *(empty)* | Inline admin list for local dev |
| `GATEWAY_ADMINS_FILE` | `/etc/ai-scan/admins/admins` | File listing admins |
| `GATEWAY_SETTINGS_KEY` | *(empty)* | Secret used to encrypt saved AI settings |

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The tests keep the gateway isolated from the real backend: they mock review
starts and status calls, and they use an isolated temporary SQLite database so
the API contracts are checked without hitting a hosted dependency.

## Site-wide AI service (admins)

Admins can configure the AI service used by the platform and save it in the
site settings database. The gateway sends that choice with every review it
starts or resumes, while never exposing the raw API key in responses.

`DELETE /reviews/{trigger_id}` is also supported: it stops a running review,
removes the record in the backend, and clears the trigger row once the owner is
allowed to do so.

## What this is not (yet)

- `GET /reviews/{trigger_id}` and the report endpoint are not yet fully gated
  by permissions; the main protection is on deep review creation.
- `pull_request` events do not yet fetch every changed file list from GitHub.
- The stored GitHub access token is not encrypted at rest in the local SQLite
  development setup.

## Repository role in the platform

This repository is the API and identity layer that sits between GitHub, the
browser, and the backend review engine. The gateway is essential for user
experience and repository trust checks, but the actual security review remains
owned by the backend and the scanner stack behind it.
