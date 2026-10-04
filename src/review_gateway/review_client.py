"""Thin HTTP client for review-api (Elad's engine). The gateway never runs a
review itself - every call here maps 1:1 to an existing review-api route.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from .config import settings


class ReviewApiError(RuntimeError):
    """review-api rejected the request or is unreachable."""


class ReviewStillRunning(ReviewApiError):
    """review-api refused because the review is mid-flight: its report is
    still being written, or there is nothing to resume. A real 409 for the
    client, not a 502 - nothing is broken, the answer is just no."""


class ReviewApiBusy(ReviewApiError):
    """A DIFFERENT review already holds the engine. review-api runs one at
    a time on purpose - a single local model would only queue against
    itself - so this means "try again shortly", not "something failed"."""


class ReviewNotFound(ReviewApiError):
    """review-api has no record of this review_id - could be a wrong id, or
    (for the report specifically) a review that hasn't finished yet. Either
    way this is a client-facing 404, not a 502 - the gateway itself and
    review-api are both fine."""


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if settings.review_api_key:
        headers["X-API-Key"] = settings.review_api_key
    return headers


def list_providers() -> dict[str, Any]:
    """The LLM endpoints review-api is configured to send reviews to.

    Read-only and unauthenticated on purpose: it returns the SHAPE of the
    deployment (which providers exist, where each runs, whether its key is
    configured) and never a key itself. Knowing that a provider named
    "lmstudio" runs on-prem tells a caller nothing they can use.
    """
    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.get("/api/v1/providers", headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code != 200:
        raise ReviewApiError(
            f"review-api error: {resp.status_code} {resp.text}"
        )
    return resp.json()


def start_review(
    repo_url: str,
    branch: str,
    files: list[str] | None,
    mode: str | None = None,
    access_token: str = "",
    findings_file: str | None = None,
    provider: str | None = None,
    llm: dict[str, str] | None = None,
) -> dict[str, Any]:
    """POST /api/v1/reviews. review_id is generated here since review-api
    requires one as its idempotency key; the gateway has no reason to reuse
    an id across separate triggers.

    access_token, when given, is the signed-in user's own GitHub token. It
    travels in the X-Repo-Token HEADER rather than the JSON body so it can
    never end up in a logged request payload, and review-api only uses it
    for the clone (see backend/src/review_api/app.py). Never log it.

    findings_file names a deterministic-scanner output already sitting in
    review-api's reports/ directory (see Code-Review-MCP/scanner) - the
    gateway does not run scanners or know their content, it only passes the
    filename through so review-api can load it and hand the model real
    evidence to enrich instead of discovering everything from scratch.

    provider NAMES one of review-api's configured endpoints. Only a name
    travels, never an address: review-api also accepts a raw `endpoint`,
    and forwarding one from a browser would turn this endpoint into an
    SSRF primitive - a caller could aim the server at 169.254.169.254 or
    at anything else it can reach but they cannot. review-api guards that
    with an allowlist, but the gateway has no reason to offer the door at
    all. The set of providers is chosen by whoever deploys the server.
    """
    review_id = f"gw-{uuid.uuid4().hex[:12]}"
    body = {
        "review_id": review_id,
        "repo_url": repo_url,
        "mode": mode or settings.default_review_mode,
        "branch": branch,
    }
    if files:
        body["files"] = files
    if findings_file:
        body["findings_file"] = findings_file
    if provider:
        body["provider"] = provider

    headers = _headers()
    if access_token:
        headers["X-Repo-Token"] = access_token
    _add_llm(body, headers, llm)

    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.post("/api/v1/reviews", json=body, headers=headers)
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code not in (200, 202, 409):
        raise ReviewApiError(f"review-api rejected the request: {resp.status_code} {resp.text}")

    result = resp.json()
    # review-api answers 409 in two different shapes, and only one of them
    # is usable. "already_running" echoes the existing job, review_id and
    # all. "busy" means a DIFFERENT review holds the engine and carries no
    # review_id at all - reading one out of it raised KeyError and the
    # caller saw a 500, so a user who simply arrived while someone else's
    # review was running was told the system had broken.
    #
    # Keyed on the field we actually need rather than on the word "busy",
    # so a reworded hint upstream cannot quietly bring the crash back.
    if "review_id" not in result:
        raise ReviewApiBusy(
            result.get("hint")
            or "review-api is busy with another review; try again shortly."
        )
    return result


def get_review_status(review_id: str, timeout: float = 10.0) -> dict[str, Any]:
    with httpx.Client(base_url=settings.review_api_base_url, timeout=timeout) as client:
        try:
            resp = client.get(f"/api/v1/reviews/{review_id}", headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        raise ReviewNotFound(f"review-api has no record of review {review_id!r}")
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def get_review_files(review_id: str) -> dict[str, Any]:
    """GET /api/v1/reviews/<id>/files - per-file progress, no issue detail.

    Separate from get_review_status because a file-tree view polls this
    while a review runs; it carries paths and state only, so polling it
    often costs far less than re-fetching the report would.
    """
    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.get(f"/api/v1/reviews/{review_id}/files",
                              headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        # Normal early in a review: the plan is written once cloning and
        # file selection are done, so "not yet" and "no such review" look
        # the same from here.
        raise ReviewNotFound(
            f"no per-file progress for review {review_id!r} yet")
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def restart_review(review_id: str, access_token: str = "") -> dict[str, Any]:
    """POST /api/v1/reviews/<id>/restart - resume a failed review.

    review-api keeps a checkpoint of the units it already finished, so a
    restart reviews ONLY what is left; the response's `restored_units`
    says how many were reused. That is the whole point of exposing this:
    a 14-hour review that died at file 79 of 123 must not start over.

    access_token matters as much here as it does for starting a review -
    the restart re-clones the repository, so without the signed-in user's
    token a private repo fails at the clone with "could not read Username
    for github.com". Same header, same reason as start_review().
    """
    headers = _headers()
    if access_token:
        headers["X-Repo-Token"] = access_token

    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.post(
                f"/api/v1/reviews/{review_id}/restart", json={}, headers=headers
            )
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        raise ReviewNotFound(f"review-api has no record of review {review_id!r}")
    if resp.status_code == 409:
        raise ReviewStillRunning(
            f"review {review_id!r} is still running; there is nothing to resume."
        )
    if resp.status_code not in (200, 202):
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def pause_review(review_id: str) -> dict[str, Any]:
    """POST /api/v1/reviews/<id>/pause - stop a running review, resumable.

    review-api answers 202 (paused, or pausing after the unit in flight in
    local mode) or 200 (already paused); 409 means there is nothing running
    to pause.
    """
    with httpx.Client(base_url=settings.review_api_base_url, timeout=15.0) as client:
        try:
            resp = client.post(f"/api/v1/reviews/{review_id}/pause",
                               json={}, headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        raise ReviewNotFound(f"review-api has no running review {review_id!r}")
    if resp.status_code == 409:
        detail = _detail(resp) or "it is not running"
        raise ReviewStillRunning(f"Nothing to pause: {detail}")
    if resp.status_code not in (200, 202):
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def resume_review(review_id: str, *, repo_url: str, branch: str, mode: str,
                  commit: str | None, access_token: str = "",
                  llm: dict[str, str] | None = None) -> dict[str, Any]:
    """POST /api/v1/reviews/<id>/resume - continue from the checkpoint.

    review-api reads repo, commit and mode from its checkpoint first; what
    is sent here is the gateway's own record, the fallback for a review
    paused before its first checkpoint (or after review-api lost the
    pause marker). The token is the CURRENT session's: the one the review
    started with may be days old and long gone. Header, never body.
    """
    body: dict[str, Any] = {"repo_url": repo_url, "branch": branch, "mode": mode}
    if commit:
        body["commit"] = commit
    headers = _headers()
    if access_token:
        headers["X-Repo-Token"] = access_token
    _add_llm(body, headers, llm)

    with httpx.Client(base_url=settings.review_api_base_url, timeout=15.0) as client:
        try:
            resp = client.post(f"/api/v1/reviews/{review_id}/resume",
                               json=body, headers=headers)
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        raise ReviewNotFound(f"nothing to resume for review {review_id!r}")
    if resp.status_code == 409:
        result = resp.json() if _is_json(resp) else {}
        if result.get("action") == "busy":
            raise ReviewApiBusy(
                "Another review is running right now. Resume this one when "
                "it finishes.")
        raise ReviewStillRunning(_detail(resp) or "This review cannot be resumed now.")
    if resp.status_code not in (200, 202):
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def _add_llm(body: dict[str, Any], headers: dict[str, str],
             llm: dict[str, str] | None) -> None:
    """The site's AI service: choice in the body, key in the X-LLM-Key
    header (like the clone token, never in a payload that might be logged)."""
    if not llm:
        return
    body["llm"] = {k: v for k, v in llm.items() if k != "api_key" and v}
    if llm.get("api_key"):
        headers["X-LLM-Key"] = llm["api_key"]


def llm_presets() -> dict[str, Any]:
    """The AI services review-api can run reviews on (public facts)."""
    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.get("/api/v1/llm/presets", headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code}")
    return resp.json()


def llm_test(llm: dict[str, str]) -> dict[str, Any]:
    """Ask review-api to reach the service and list its models. A bad
    choice (unknown service, public address for "local") is a 400 whose
    sentence is returned as the error, like an unreachable service."""
    body: dict[str, Any] = {}
    headers = _headers()
    _add_llm(body, headers, llm)
    with httpx.Client(base_url=settings.review_api_base_url, timeout=30.0) as client:
        try:
            resp = client.post("/api/v1/llm/models", json=body, headers=headers)
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc
    if resp.status_code == 400:
        return {"reachable": False, "error": _detail(resp) or "Not a usable choice."}
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code}")
    return resp.json()


def delete_review(review_id: str) -> dict[str, Any]:
    """DELETE /api/v1/reviews/<id>: every file the review left. 404 when
    there is nothing left on review-api's side (already deleted)."""
    with httpx.Client(base_url=settings.review_api_base_url, timeout=15.0) as client:
        try:
            resp = client.delete(f"/api/v1/reviews/{review_id}", headers=_headers())
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc
    if resp.status_code == 404:
        raise ReviewNotFound(f"nothing stored for review {review_id!r}")
    if resp.status_code == 409:
        raise ReviewStillRunning(_detail(resp) or "The review is still running.")
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def _is_json(resp: httpx.Response) -> bool:
    return resp.headers.get("content-type", "").startswith(
        ("application/json", "application/problem+json"))


def _detail(resp: httpx.Response) -> str:
    """review-api's problem-detail sentence, when it sent one."""
    try:
        return str(resp.json().get("detail") or "")
    except ValueError:
        return ""


def delete_review_report(review_id: str) -> dict[str, Any]:
    """DELETE /api/v1/reports/<name>.

    review-api names report files after the review_id, so `<id>.json` is
    the artifact to remove; it also removes that report's `.md` and
    `.notes.md` siblings, and deliberately KEEPS the resume checkpoint so
    an interrupted review can still be restarted (see delete_report in
    backend/src/review_api/app.py).
    """
    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.delete(
                f"/api/v1/reports/{review_id}.json", headers=_headers()
            )
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        raise ReviewNotFound(f"no report to delete for review {review_id!r}")
    if resp.status_code == 409:
        raise ReviewStillRunning(
            f"review {review_id!r} is still running; cancel it before deleting."
        )
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    return resp.json()


def get_review_report(review_id: str, view: str = "full") -> dict[str, Any] | str:
    """review-api's /report defaults to "summary" (file names + issue
    COUNTS only, no detail) - not very useful as the thing a user actually
    reads, so the gateway asks for "full" (every issue: severity, line,
    description, suggested fix) unless told otherwise. "summary" and
    "markdown" are the other view= values review-api understands.

    view=markdown comes back as text/markdown, not JSON - resp.json() would
    raise on it. Returned as a plain str in that case; every other view
    returns the parsed dict as before."""
    with httpx.Client(base_url=settings.review_api_base_url, timeout=10.0) as client:
        try:
            resp = client.get(
                f"/api/v1/reviews/{review_id}/report",
                params={"view": view},
                headers=_headers(),
            )
        except httpx.RequestError as exc:
            raise ReviewApiError(f"Cannot reach review-api: {exc}") from exc

    if resp.status_code == 404:
        # Most often means "not finished yet" (review-api only writes the
        # report on completion) rather than a wrong id - the caller (our
        # own polling UI) treats both the same: not ready, try again later.
        raise ReviewNotFound(f"no report yet for review {review_id!r}")
    if resp.status_code != 200:
        raise ReviewApiError(f"review-api error: {resp.status_code} {resp.text}")
    if view == "markdown":
        return resp.text
    return resp.json()
