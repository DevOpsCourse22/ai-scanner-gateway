"""GitHub webhook verification and payload parsing.

Signature verification is unchanged from the original Track 3 spike
(app.py at the repo root) - HMAC-SHA256 over the raw body, constant-time
compare. What's new here is extract_trigger_info: turning a push/pull_request
payload into just {repo_url, branch, files}, since this gateway no longer
clones anything itself - review-api's mcp-server engine does that.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

_REPO_URL_RE = re.compile(
    r"^https://(?P<host>[a-zA-Z0-9.-]+)/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(\.git)?/?$"
)
ALLOWED_HOSTS = {"github.com"}


def verify_github_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Recompute the HMAC-SHA256 GitHub sent and compare in constant time."""
    if not secret:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    provided = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


def validate_repo_url(repo_url: str) -> None:
    """Defense in depth: refuse to forward anything that isn't a plain
    https://github.com/<owner>/<repo> URL, even though it came from a
    signature-verified GitHub payload."""
    match = _REPO_URL_RE.match(repo_url.strip())
    if not match or match.group("host") not in ALLOWED_HOSTS:
        raise ValueError(f"Rejected repo URL: {repo_url!r}")


def parse_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """https://github.com/<owner>/<repo>(.git) -> (owner, repo), or None if
    it doesn't match. Used by the deep-mode ownership gate."""
    match = _REPO_URL_RE.match(repo_url.strip())
    if not match:
        return None
    return match.group("owner"), match.group("repo")


@dataclass
class TriggerInfo:
    repo_url: str
    branch: str
    files: list[str] | None
    commit_sha: str | None


def extract_trigger_info(event_type: str, payload: dict) -> TriggerInfo | None:
    """Pull {repo_url, branch, files} out of a push/pull_request payload.

    Returns None for event types we don't act on (ping, issues, ...).
    """
    repo = payload.get("repository", {})
    clone_url = repo.get("clone_url")
    if not clone_url:
        return None

    if event_type == "push":
        ref = payload.get("ref", "")
        branch = ref.removeprefix("refs/heads/") if ref else ""
        files: set[str] = set()
        for commit in payload.get("commits", []):
            files.update(commit.get("added", []))
            files.update(commit.get("modified", []))
        return TriggerInfo(
            repo_url=clone_url,
            branch=branch,
            files=sorted(files) or None,
            commit_sha=payload.get("after"),
        )

    if event_type == "pull_request":
        pr = payload.get("pull_request", {})
        # GitHub doesn't include the changed-file list on the pull_request
        # payload itself (that needs a separate GET .../pulls/<n>/files call
        # - not built yet). files=None means review-api reviews everything.
        return TriggerInfo(
            repo_url=clone_url,
            branch=pr.get("head", {}).get("ref", ""),
            files=None,
            commit_sha=pr.get("head", {}).get("sha"),
        )

    return None
