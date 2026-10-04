"""GitHub OAuth (Authorization Code flow) + the ADR-006 ownership check.

client_id/client_secret are read from Settings only - this module never
touches os.environ directly, so there is exactly one place a leak could
start. The exchange and permission calls run server-to-server (gateway to
GitHub); the browser is only ever redirected, never handed a token.
"""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx

from .config import settings

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"


class GitHubOAuthError(RuntimeError):
    """GitHub rejected the flow, or couldn't be reached."""


def new_state() -> str:
    """Unguessable value GitHub echoes back on the callback - lets us tell a
    real completion of a login WE started from a forged callback request
    (CSRF on the OAuth flow itself)."""
    return secrets.token_urlsafe(24)


def build_authorize_url(state: str) -> str:
    params = {
        "client_id": settings.github_oauth_client_id,
        "redirect_uri": settings.github_oauth_redirect_uri,
        # "repo" (not "public_repo") because ownership verification needs to
        # read permissions on PRIVATE repos too - see check_repo_permission.
        "scope": "repo",
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code_for_token(code: str) -> str:
    """POST the callback's code to GitHub for a real access token. This is
    the step that needs client_secret - it never leaves this function."""
    with httpx.Client(timeout=10.0) as client:
        try:
            resp = client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.github_oauth_client_id,
                    "client_secret": settings.github_oauth_client_secret,
                    "code": code,
                    "redirect_uri": settings.github_oauth_redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.RequestError as exc:
            raise GitHubOAuthError(f"Cannot reach GitHub: {exc}") from exc

    if resp.status_code != 200:
        raise GitHubOAuthError(f"GitHub token exchange failed: {resp.status_code} {resp.text}")
    data = resp.json()
    if "error" in data:
        raise GitHubOAuthError(
            f"GitHub rejected the code: {data.get('error_description', data['error'])}"
        )
    token = data.get("access_token")
    if not token:
        raise GitHubOAuthError("GitHub response had no access_token")
    return token


def fetch_github_user(access_token: str) -> dict[str, Any]:
    """Who did the user just prove they are."""
    with httpx.Client(timeout=10.0) as client:
        try:
            resp = client.get(
                USER_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except httpx.RequestError as exc:
            raise GitHubOAuthError(f"Cannot reach GitHub: {exc}") from exc

    if resp.status_code != 200:
        raise GitHubOAuthError(f"GitHub /user failed: {resp.status_code} {resp.text}")
    return resp.json()


def check_repo_permission(access_token: str, owner: str, repo: str, username: str) -> str:
    """ADR-006 ownership verification: what access does this GitHub user
    actually have on this specific repo. One of admin|write|read|none -
    "none" also covers repos that don't exist or the token can't see."""
    url = f"https://api.github.com/repos/{owner}/{repo}/collaborators/{username}/permission"
    with httpx.Client(timeout=10.0) as client:
        try:
            resp = client.get(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except httpx.RequestError as exc:
            raise GitHubOAuthError(f"Cannot reach GitHub: {exc}") from exc

    if resp.status_code == 404:
        return "none"
    if resp.status_code != 200:
        raise GitHubOAuthError(f"GitHub permission check failed: {resp.status_code} {resp.text}")
    return resp.json().get("permission", "none")
