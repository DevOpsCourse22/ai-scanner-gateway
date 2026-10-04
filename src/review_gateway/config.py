"""All gateway settings, env-overridable. Kept deliberately small for the
skeleton — no ${VAR} interpolation or YAML file like review_api/config.py;
add that later if the gateway grows enough to need it.

load_dotenv() runs here, at import time, deliberately BEFORE Settings() is
constructed below - the field factories read os.environ, so .env has to be
loaded first or every value would come back empty. python-dotenv's default
(override=False) never clobbers a variable the shell/conftest.py already
set, which is what keeps tests deterministic even if a real .env exists on
someone's machine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    # Shared secret configured on the GitHub webhook (Settings -> Webhooks).
    # Never hardcode; refusing all webhooks with no secret set is intentional.
    github_webhook_secret: str = field(
        default_factory=lambda: os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    )

    # Base URL of Elad's review-api (the engine). This gateway calls it; it
    # never runs a review or clones a repo itself.
    review_api_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "REVIEW_API_BASE_URL", "http://localhost:8000"
        )
    )
    # Matches review-api's REVIEW_API_KEY / X-API-Key header, if that server
    # has one configured. Empty is fine against a local, unauthenticated
    # review-api.
    review_api_key: str = field(
        default_factory=lambda: os.environ.get("REVIEW_API_KEY", "")
    )

    # SQLite by default for local dev; point at a real Postgres URL in
    # deployment (e.g. postgresql+psycopg://user:pass@host/db).
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "GATEWAY_DATABASE_URL", "sqlite:///./gateway.db"
        )
    )

    default_review_mode: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_DEFAULT_MODE", "brief")
    )

    # --- GitHub OAuth ------------------------------------------------------
    # From the OAuth App registered at github.com/settings/developers.
    # client_id is not sensitive (GitHub treats it as public); client_secret
    # absolutely is - env var only, never logged, never returned by any route.
    github_oauth_client_id: str = field(
        default_factory=lambda: os.environ.get("GITHUB_OAUTH_CLIENT_ID", "")
    )
    github_oauth_client_secret: str = field(
        default_factory=lambda: os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "")
    )
    # Must exactly match the "Authorization callback URL" configured on the
    # GitHub OAuth App.
    github_oauth_redirect_uri: str = field(
        default_factory=lambda: os.environ.get(
            "GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8080/auth/github/callback"
        )
    )

    # How long a login lasts before re-authentication is required, regardless
    # of whether the underlying GitHub token is still valid.
    session_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("GATEWAY_SESSION_TTL_SECONDS", 28800))
    )
    # False for local http:// dev; MUST be true once served over https in
    # deployment, or the session cookie is sent in the clear.
    cookie_secure: bool = field(
        default_factory=lambda: os.environ.get("GATEWAY_COOKIE_SECURE", "false").lower() == "true"
    )

    # Comma-separated origins allowed to call the gateway with credentials
    # (cookies) from a browser - the React dev server's origin by default.
    # Cookie-based auth requires an explicit origin list; "*" is rejected by
    # browsers once allow_credentials=True.
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.environ.get("GATEWAY_CORS_ORIGINS", "http://localhost:5173").split(",")
            if o.strip()
        ]
    )

    # Where /auth/github/callback sends the browser after a successful
    # login - the React app, not the gateway's own JSON.
    frontend_url: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_FRONTEND_URL", "http://localhost:5173")
    )

    # --- site administration ------------------------------------------------
    # Who may change site-wide settings (the AI model), as GitHub usernames
    # or "id:<numeric GitHub id>", one per line or comma-separated. Read
    # from a FILE so that, in the cluster, it is a ConfigMap mounted as a
    # volume: `kubectl edit configmap gateway-admins` changes it and the
    # gateway sees the new list within a minute, with no restart. The env
    # var is the local-dev route; both lists are merged.
    admins_file: str = field(
        default_factory=lambda: os.environ.get(
            "GATEWAY_ADMINS_FILE", "/etc/ai-scan/admins/admins"))
    admins: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_ADMINS", ""))
    # Encrypts the AI service's API key at rest. Any long random string
    # (`openssl rand -hex 32`), from a Secret. Without it, a key can't be
    # saved, but a key-less service (local LM Studio) still can. Changing
    # it makes the stored key unreadable: an admin then enters it again.
    settings_encryption_key: str = field(
        default_factory=lambda: os.environ.get("GATEWAY_SETTINGS_KEY", ""))


settings = Settings()
