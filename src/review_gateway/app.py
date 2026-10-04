"""API Gateway - the component the team's architecture docs call
"API Gateway / FastAPI" (docs/03-high-level-design/04-component-architecture.md).

Receives GitHub webhooks AND manual/dashboard requests, and hands actual
review work to review-api. quick/brief stay open; deep mode requires GitHub
login + repo access (see README, _require_deep_access below). Owns no
review state of its own beyond "which review-api job did this trigger
start" - see db.py.

    POST /webhook                    GitHub calls this
    POST /reviews                    manual trigger (future: from the Dashboard)
    GET  /reviews/{trigger_id}       poll status of a trigger
    POST /reviews/{trigger_id}/pause stop a running review, resumable later
    POST /reviews/{trigger_id}/resume continue it, days later if need be
    DELETE /reviews/{trigger_id}     delete the review and everything it stored
    GET  /providers/ai               the site's AI service (any signed-in user)
    PUT  /providers/ai               change it (admins)
    DELETE /providers/ai             back to the server's default (admins)
    POST /providers/ai/test          reach a service and list its models (admins)
    GET  /providers/ai/presets       the services one can choose
    GET  /reviews/{trigger_id}/report
    GET  /auth/github/login          start GitHub OAuth (redirects)
    GET  /auth/github/callback       GitHub redirects back here
    GET  /auth/me                    who is the current session (requires login)
    GET  /auth/me/settings           the signed-in user's preferences
    PUT  /auth/me/settings
    POST /auth/logout
    GET  /health
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator, Literal

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import github_auth, github_oauth, review_client, site_settings
from .config import settings
from .db import AuthSession, Trigger, UserSettings, get_session, init_db

STATE_COOKIE = "oauth_state"
SESSION_COOKIE = "session_id"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("review_gateway")

app = FastAPI(title="review-gateway")
init_db()

# The React app runs on a different origin (Vite dev server) than the
# gateway, and needs cookies (the session) sent cross-origin - that requires
# an explicit origin list, not "*", once allow_credentials=True.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db() -> Iterator[Session]:
    db = get_session()
    try:
        yield db
    finally:
        db.close()


def get_current_session(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    """Dependency for routes that require login."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise HTTPException(status_code=401, detail="not logged in")
    session = db.get(AuthSession, session_id)
    if session is None or session.is_expired():
        raise HTTPException(status_code=401, detail="session missing or expired")
    return session


def get_current_session_optional(request: Request, db: Session = Depends(get_db)) -> AuthSession | None:
    """Same lookup as get_current_session, but returns None instead of
    raising - for routes where login is optional (quick/brief) but we still
    want to attribute the trigger to a user when one happens to be logged in."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    session = db.get(AuthSession, session_id)
    if session is None or session.is_expired():
        return None
    return session


def _require_deep_access(request: Request, repo_url: str, db: Session) -> AuthSession:
    """ADR-006 gate for Deep Reports only - quick/brief stay open to
    anonymous callers, matching the Summary Report tier in
    docs/01-executive-summary.md. Team decision (2026-08-15): deep-only for
    now; easy to widen later if we decide otherwise - see github_oauth.py.
    """
    session = get_current_session(request, db)

    parsed = github_auth.parse_owner_repo(repo_url)
    if parsed is None:
        raise HTTPException(status_code=400, detail="cannot parse owner/repo from repo_url")
    owner, repo = parsed

    try:
        permission = github_oauth.check_repo_permission(
            session.github_access_token, owner, repo, session.github_login
        )
    except github_oauth.GitHubOAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if permission == "none":
        raise HTTPException(
            status_code=403,
            detail=f"{session.github_login} has no access to {owner}/{repo}",
        )
    return session


@app.get("/auth/github/login")
def github_login():
    """Redirects the browser to GitHub's consent screen. The state cookie
    only needs to survive this one round trip (login -> GitHub -> callback),
    so it gets a short max_age independent of the real session TTL."""
    state = github_oauth.new_state()
    resp = RedirectResponse(url=github_oauth.build_authorize_url(state))
    resp.set_cookie(
        STATE_COOKIE, state, httponly=True, secure=settings.cookie_secure,
        samesite="lax", max_age=600,
    )
    return resp


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str = "", state: str = "", db: Session = Depends(get_db)):
    expected_state = request.cookies.get(STATE_COOKIE)
    if not state or not expected_state or state != expected_state:
        log.warning("Rejected OAuth callback: state mismatch (possible CSRF)")
        raise HTTPException(status_code=400, detail="invalid or missing OAuth state")
    if not code:
        raise HTTPException(status_code=400, detail="missing code")

    try:
        access_token = github_oauth.exchange_code_for_token(code)
        user = github_oauth.fetch_github_user(access_token)
    except github_oauth.GitHubOAuthError as exc:
        log.error("GitHub OAuth callback failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    session = AuthSession(
        github_user_id=user["id"],
        github_login=user["login"],
        github_access_token=access_token,
        expires_at=AuthSession.new_expiry(),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    log.info("GitHub login: user=%s session=%s", session.github_login, session.id[:8])

    # Send the browser back to the app, not to a raw JSON page on the
    # gateway's own origin - the frontend picks up the new session itself
    # on load via GET /auth/me, no query params needed.
    resp = RedirectResponse(url=settings.frontend_url)
    resp.delete_cookie(STATE_COOKIE)
    resp.set_cookie(
        SESSION_COOKIE, session.id, httponly=True, secure=settings.cookie_secure,
        samesite="lax", max_age=settings.session_ttl_seconds,
    )
    return resp


@app.get("/auth/me")
def whoami(session: AuthSession = Depends(get_current_session)):
    return {
        "login": session.github_login,
        "github_user_id": session.github_user_id,
        # Built from the numeric id, which GitHub serves without a token and
        # which survives a username change - nothing to store or refresh.
        "avatar_url": f"https://avatars.githubusercontent.com/u/{session.github_user_id}?s=96",
        "session_expires_at": _iso(session.expires_at),
        # Admins may change site-wide settings (Settings, AI model). Who is
        # one is a ConfigMap, not a database row: see site_settings.py.
        "is_admin": site_settings.is_admin(session),
    }


class UserPrefs(BaseModel):
    """Everything the Settings page can change. Unknown keys are refused
    (extra="forbid") so a typo cannot silently store nothing."""

    model_config = {"extra": "forbid"}

    theme: Literal["system", "light", "dark"] = "system"
    motion: Literal["system", "reduce", "full"] = "system"
    default_mode: Literal["quick", "brief", "deep"] = "brief"
    default_branch: str = Field(default="", max_length=255)
    # Ask before pausing a deep review: a pause in kubernetes mode drops the
    # file in flight, which on a large file is real work.
    confirm_pause: bool = True


def _prefs_for(github_user_id: int, db: Session) -> UserPrefs:
    row = db.get(UserSettings, github_user_id)
    stored = row.load() if row else {}
    known = {k: v for k, v in stored.items() if k in UserPrefs.model_fields}
    try:
        return UserPrefs(**known)
    except ValueError:
        return UserPrefs()        # a value from an older version: defaults


@app.get("/auth/me/settings")
def get_my_settings(session: AuthSession = Depends(get_current_session),
                    db: Session = Depends(get_db)):
    return _prefs_for(session.github_user_id, db).model_dump()


@app.put("/auth/me/settings")
def put_my_settings(prefs: UserPrefs,
                    session: AuthSession = Depends(get_current_session),
                    db: Session = Depends(get_db)):
    row = db.get(UserSettings, session.github_user_id)
    if row is None:
        row = UserSettings(github_user_id=session.github_user_id)
        db.add(row)
    row.prefs = json.dumps(prefs.model_dump())
    db.commit()
    return prefs.model_dump()


@app.post("/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        session = db.get(AuthSession, session_id)
        if session is not None:
            db.delete(session)
            db.commit()
    resp = JSONResponse({"status": "logged_out"})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


class ManualReviewRequest(BaseModel):
    """Body for POST /reviews - the manual/dashboard trigger path. quick/brief
    accept any caller; deep requires login + repo access (_require_deep_access).

    Length caps are defense in depth, not the real validation - repo_url's
    actual shape is checked by github_auth.validate_repo_url() right after.
    They exist so a client mistake (or abuse) can't send an arbitrarily
    large string this far into the request pipeline at all.
    """

    repo_url: str = Field(max_length=512)
    branch: str = Field(default="", max_length=255)
    files: list[str] | None = Field(default=None, max_length=200)
    mode: str | None = None
    # Names a deterministic-scanner output already produced by
    # Code-Review-MCP/scanner and sitting in review-api's reports/ dir - see
    # that component's README. The gateway never runs a scan or reads this
    # file itself, only forwards the name.
    findings_file: str | None = Field(default=None, max_length=255)
    # NAMES one of review-api's configured LLM endpoints ("lmstudio", a
    # hosted API, ...). A name, never an address: review-api also accepts a
    # raw endpoint, and taking one from a browser would make this an SSRF
    # primitive - the caller could aim the server at 169.254.169.254, or at
    # anything else it can reach and they cannot. Which providers exist is
    # a deployment decision, not a request parameter.
    provider: str | None = Field(default=None, max_length=64)


def _start_and_record_review(
    *,
    repo_url: str,
    branch: str,
    files: list[str] | None,
    trigger_source: str,
    commit_sha: str | None,
    mode: str | None,
    github_user_id: int | None,
    access_token: str,
    findings_file: str | None,
    provider: str | None,
    db: Session,
) -> Trigger:
    """Shared by /webhook and /reviews: validate, call review-api, record
    the trigger -> review_id mapping. Raises HTTPException on failure.

    access_token is the signed-in user's own GitHub token, forwarded so
    review-api can clone a PRIVATE repo the user has access to. Empty for
    webhooks and for anonymous callers - those fall back to whatever
    GITHUB_TOKEN review-api itself is configured with, which is how it
    behaved before. It is never stored on the Trigger row: the token
    belongs to the session, and outliving it would turn our thin mapping
    table into a credential store."""
    try:
        github_auth.validate_repo_url(repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    llm = _site_llm(db)
    try:
        result = review_client.start_review(
            repo_url=repo_url,
            branch=branch,
            files=files,
            mode=mode,
            access_token=access_token,
            findings_file=findings_file,
            provider=provider,
            llm=llm,
        )
    except review_client.ReviewApiBusy as exc:
        # 409, not 502: review-api is healthy and deliberately serialises
        # reviews. Telling the user "try again shortly" is the truth; a 502
        # would send them looking for a fault that does not exist.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        log.error("review-api call failed: %s", exc)
        raise HTTPException(status_code=502, detail=_scrub(str(exc), llm)) from exc

    trigger = Trigger(
        github_event=trigger_source,
        repo_url=repo_url,
        branch=branch,
        mode=mode or settings.default_review_mode,
        commit_sha=commit_sha,
        review_id=result["review_id"],
        github_user_id=github_user_id,
        status=result.get("status") or "requested",
        status_updated_at=datetime.now(timezone.utc),
    )
    db.add(trigger)
    db.commit()
    db.refresh(trigger)
    return trigger


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/webhook")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    raw_body = await request.body()

    if not github_auth.verify_github_signature(
        raw_body, signature_header, settings.github_webhook_secret
    ):
        log.warning("Rejected webhook: invalid or missing signature (event=%s)", event_type)
        raise HTTPException(status_code=401, detail="invalid signature")

    payload = await request.json()
    log.info("Verified webhook received: event=%s", event_type)

    if event_type == "ping":
        return {"message": "pong"}

    trigger_info = github_auth.extract_trigger_info(event_type, payload)
    if trigger_info is None:
        return {"status": "ignored", "event": event_type}

    trigger = _start_and_record_review(
        repo_url=trigger_info.repo_url,
        branch=trigger_info.branch,
        files=trigger_info.files,
        trigger_source=event_type,
        commit_sha=trigger_info.commit_sha,
        mode=None,
        # No browser session exists for a webhook call - GitHub is a
        # server, not a logged-in user. So there is no user token to
        # forward either; review-api falls back to its own GITHUB_TOKEN.
        github_user_id=None,
        access_token="",
        # No scan has run for this push - see the module docstring on
        # scanner/README.md: today the scanner is a manual/CI step, not
        # something the gateway or a webhook triggers automatically.
        findings_file=None,
        # A webhook expresses no preference, so review-api uses its own
        # default provider - the same behaviour as before this existed.
        provider=None,
        db=db,
    )

    return {
        "status": "accepted",
        "event": event_type,
        "trigger_id": trigger.id,
        "review_id": trigger.review_id,
    }


@app.post("/reviews")
def create_review_manual(
    request: Request,
    body: ManualReviewRequest,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Manual trigger - what the Dashboard calls. quick/brief stay open to
    anyone; deep requires login + repo access. Login is optional either way
    for THIS gate, but if the caller happens to be logged in, the trigger
    is attributed to them (see GET /reviews for "my history")."""
    try:
        github_auth.validate_repo_url(body.repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mode = body.mode or settings.default_review_mode
    if mode == "deep":
        # Validated above, so this can only fail on a bug in the regex - the
        # host is already known-good (github.com) at this point.
        _require_deep_access(request, body.repo_url, db)

    trigger = _start_and_record_review(
        repo_url=body.repo_url,
        branch=body.branch,
        files=body.files,
        trigger_source="manual",
        commit_sha=None,
        mode=body.mode,
        github_user_id=session.github_user_id if session else None,
        # Lets a signed-in user scan their own PRIVATE repos. Anonymous
        # callers send nothing, so they stay limited to public repos.
        access_token=session.github_access_token if session else "",
        findings_file=body.findings_file,
        provider=body.provider,
        db=db,
    )

    return {
        "status": "accepted",
        "event": "manual",
        "trigger_id": trigger.id,
        "review_id": trigger.review_id,
    }


@app.get("/reviews")
def list_my_reviews(
    db: Session = Depends(get_db),
    session: AuthSession = Depends(get_current_session),
):
    """"My history" - only triggers started while YOU were logged in.
    Webhook triggers and triggers started while logged out never have a
    github_user_id (see _start_and_record_review), so they never show up
    here for anyone - there's no "everyone's history" view."""
    triggers = db.execute(
        select(Trigger)
        .where(Trigger.github_user_id == session.github_user_id)
        .order_by(Trigger.created_at.desc())
        .limit(50)
    ).scalars().all()
    _refresh_live(triggers, db)
    return [_trigger_summary(t) for t in triggers]


@app.get("/providers")
def list_providers():
    """Which LLM endpoints this deployment can send a review to.

    The dashboard needs this to offer a choice at all, and the choice is
    the point: it is what decouples a review from one particular machine
    being awake. A provider can be a laptop on the LAN, a box in a server
    room, or a hosted API - the review pipeline does not change either way.

    Unauthenticated, like the review form itself (quick and brief need no
    login). What comes back is the deployment's SHAPE - names, whether each
    one runs on-prem or in a cloud, whether its key is configured - never a
    key and never anything that lets a caller reach an endpoint they could
    not already reach themselves.

    Degrades to an empty list rather than an error: not being able to offer
    a choice is a smaller problem than a dashboard that will not load, and
    the review still works on review-api's default.
    """
    try:
        return review_client.list_providers()
    except review_client.ReviewApiError as exc:
        log.warning("Could not list providers: %s", exc)
        return {"default": None, "providers": [], "unavailable": True}


# --- the site's AI service (Settings, AI model) ------------------------------

def _site_llm(db: Session) -> dict[str, str] | None:
    """What every review runs on, or None for review-api's own default. A
    key that can't be read stops the review before it starts, with the
    reason, rather than letting the AI service answer 401 much later."""
    try:
        return site_settings.ai_for_review(db)
    except (site_settings.SettingsKeyChanged, site_settings.SettingsKeyMissing) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _scrub(text: str, llm: dict[str, str] | None) -> str:
    key = (llm or {}).get("api_key")
    return text.replace(key, "[key]") if key else text


def _require_admin(session: AuthSession = Depends(get_current_session)) -> AuthSession:
    if not site_settings.is_admin(session):
        raise HTTPException(
            status_code=403,
            detail="Only site admins can change this. Admins are listed in "
                   "the gateway-admins ConfigMap.")
    return session


class AiSettingsBody(BaseModel):
    preset: str = Field(pattern=r"^[a-z_]{1,32}$")
    endpoint: str = Field(default="", max_length=255)
    model: str = Field(default="", max_length=255)
    # Write-only. Empty keeps the saved key (if the service did not change).
    api_key: str = Field(default="", max_length=4096)
    clear_key: bool = False

    model_config = {"extra": "forbid"}


@app.get("/providers/ai")
def get_ai_settings(session: AuthSession = Depends(get_current_session),
                    db: Session = Depends(get_db)):
    return {**site_settings.ai_public(db),
            "can_edit": site_settings.is_admin(session),
            "encryption_ready": site_settings.encryption_ready()}


@app.get("/providers/ai/presets")
def get_ai_presets(session: AuthSession = Depends(get_current_session)):
    try:
        return review_client.llm_presets()
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/providers/ai")
def put_ai_settings(body: AiSettingsBody,
                    session: AuthSession = Depends(_require_admin),
                    db: Session = Depends(get_db)):
    try:
        saved = site_settings.save_ai(
            db, preset=body.preset, endpoint=body.endpoint.strip(),
            model=body.model.strip(), api_key=body.api_key.strip() or None,
            clear_key=body.clear_key, who=session.github_login)
    except site_settings.SettingsKeyMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    log.info("AI service set to %s by %s", body.preset, session.github_login)
    return {**saved, "can_edit": True,
            "encryption_ready": site_settings.encryption_ready()}


@app.delete("/providers/ai")
def delete_ai_settings(session: AuthSession = Depends(_require_admin),
                       db: Session = Depends(get_db)):
    site_settings.clear_ai(db)
    log.info("AI service reset to the server default by %s", session.github_login)
    return {"configured": False, "can_edit": True,
            "encryption_ready": site_settings.encryption_ready()}


@app.post("/providers/ai/test")
def test_ai_settings(body: AiSettingsBody,
                     session: AuthSession = Depends(_require_admin),
                     db: Session = Depends(get_db)):
    """Reach the service and list its models, before or after saving. An
    empty api_key tests with the saved one, if it is for the same service."""
    try:
        key = body.api_key.strip() or (
            "" if body.clear_key else site_settings.saved_key_for(db, body.preset))
    except site_settings.SettingsKeyChanged as exc:
        return {"reachable": False, "error": str(exc)}
    except site_settings.SettingsKeyMissing:
        key = ""
    llm = {"preset": body.preset, "endpoint": body.endpoint.strip(),
           "model": body.model.strip(), "api_key": key}
    try:
        result = review_client.llm_test(llm)
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=_scrub(str(exc), llm)) from exc
    if result.get("error"):
        result["error"] = _scrub(result["error"], llm)
    return result


def _trigger_readable_by(
    trigger_id: str, session: AuthSession | None, db: Session
) -> Trigger:
    """Load a trigger the caller is allowed to READ, or 404.

    Two kinds of trigger, two rules:

    * Started while logged in (github_user_id set) - only that user may read
      it. This is what closes the hole: a deep review on someone's PRIVATE
      repo is always logged-in-owned, so it can never be read by anyone else.
    * Started anonymously, or by a webhook (github_user_id NULL) - there is
      no owner to compare against, so possession of the trigger_id is the
      credential. That is deliberate, not an oversight: quick/brief need no
      login, and the id is an unguessable UUID.

    A trigger owned by someone else returns 404, NOT 403 - "no such review"
    rather than "exists, but not yours", so the endpoint can't be used to
    probe which ids are real. (docs/12-roadmap Phase 3 calls this
    "non-disclosing denial behavior".)
    """
    trigger = db.get(Trigger, trigger_id)
    if trigger is None:
        raise HTTPException(status_code=404, detail=f"no trigger {trigger_id!r}")
    if trigger.github_user_id is not None and (
        session is None or session.github_user_id != trigger.github_user_id
    ):
        raise HTTPException(status_code=404, detail=f"no trigger {trigger_id!r}")
    return trigger


@app.get("/reviews/{trigger_id}")
def get_review(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    trigger = _trigger_readable_by(trigger_id, session, db)

    try:
        payload = review_client.get_review_status(trigger.review_id)
    except review_client.ReviewNotFound as exc:
        # review-api has no file left for it either (say, its report was
        # deleted). What we last saw is still the truth worth showing - a
        # 404 here used to make a finished review look like it never ran.
        if trigger.status:
            return {**_cached_status(trigger), "trigger": _trigger_summary(trigger)}
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _remember(trigger, payload, db)
    return {**payload, "trigger": _trigger_summary(trigger)}


@app.post("/reviews/{trigger_id}/pause")
def pause_review(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Pause a running review. It stays resumable for as long as its
    checkpoint is on the reports volume - days, if need be.

    Same authorization as reading it (_trigger_readable_by): an owned
    review only by its owner, an anonymous one by its trigger id.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)
    try:
        payload = review_client.pause_review(trigger.review_id)
    except review_client.ReviewNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewStillRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _remember(trigger, payload, db)
    return {**payload, "trigger": _trigger_summary(trigger)}


@app.post("/reviews/{trigger_id}/resume")
def resume_review(
    trigger_id: str,
    request: Request,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Resume a paused, failed or interrupted review from its checkpoint.

    Sends review-api what this trigger recorded (repo, branch, mode, the
    last commit seen) as the fallback for a review it has no files for, and
    the CURRENT session's token: someone resuming two days later signed in
    again, and the token the review started with belongs to a session that
    is gone. A deep review re-checks repository access for the same reason.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)
    if trigger.mode == "deep":
        _require_deep_access(request, trigger.repo_url, db)
    try:
        payload = review_client.resume_review(
            trigger.review_id, repo_url=trigger.repo_url,
            branch=trigger.branch, mode=trigger.mode,
            commit=trigger.commit_sha,
            access_token=session.github_access_token if session else "",
            llm=_site_llm(db))
    except review_client.ReviewNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewApiBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewStillRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    trigger.paused_at = None
    _remember(trigger, payload, db)
    return {**payload, "trigger": _trigger_summary(trigger)}


# --- the trigger's cached view of its review ---------------------------------

# Statuses that will change on their own. Anything else (completed, failed,
# cancelled, paused, interrupted) only changes when someone acts on it.
_LIVE = {"requested", "cloning", "scanning", "reviewing", "retrying"}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:  # SQLite drops tzinfo on round-trip
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _overall_percent(payload: dict[str, Any]) -> int | None:
    """Progress against the whole review. After a resume, review-api's
    done/total count only what is LEFT and restored_units what the
    checkpoint gave back, so 0% of the remainder can be 60% overall."""
    if payload.get("status") == "completed":
        return 100
    done, total = payload.get("done"), payload.get("total")
    restored = payload.get("restored_units") or 0
    if isinstance(done, int) and isinstance(total, int) and total + restored > 0:
        return round(100 * (done + restored) / (total + restored))
    percent = payload.get("percent")
    return percent if isinstance(percent, int) else None


def _remember(trigger: Trigger, payload: dict[str, Any], db: Session) -> None:
    """Keep the last status review-api reported, for the history list and
    for the day review-api no longer remembers this review."""
    status = payload.get("status")
    if not isinstance(status, str) or not status or status == "busy":
        return
    trigger.status = status[:32]
    percent = _overall_percent(payload)
    if percent is not None:
        trigger.percent = percent
    restored = payload.get("restored_units") or 0
    if isinstance(payload.get("done"), int):
        trigger.units_done = payload["done"] + restored
    if isinstance(payload.get("total"), int):
        trigger.units_total = payload["total"] + restored
    commit = payload.get("commit")
    if isinstance(commit, str) and len(commit) == 40:
        # Only a full SHA can pin a resume; a short one is display-only.
        trigger.commit_sha = commit
    if payload.get("model"):
        trigger.model = str(payload["model"])[:255]
    error = payload.get("error")
    trigger.last_error = str(error)[:1000] if error and status != "completed" else None
    if status == "paused":
        trigger.paused_at = _parse_time(payload.get("paused_at")) or trigger.paused_at \
            or datetime.now(timezone.utc)
    elif status in _LIVE:
        trigger.paused_at = None
    if status not in _LIVE:
        trigger.finished_at = (_parse_time(payload.get("finished_at"))
                               or trigger.finished_at)
    else:
        trigger.finished_at = None
    trigger.status_updated_at = datetime.now(timezone.utc)
    db.commit()


def _refresh_live(triggers: list[Trigger], db: Session, limit: int = 10) -> None:
    """Ask review-api about the reviews that may have moved since we last
    looked (live ones, and old rows with no cached status). Bounded, with a
    short timeout, and it stops at the first failure: the list must load
    even when review-api is down, showing what was last known."""
    stale = [t for t in triggers if t.status is None or t.status in _LIVE][:limit]
    for trigger in stale:
        try:
            payload = review_client.get_review_status(trigger.review_id, timeout=3.0)
        except review_client.ReviewNotFound:
            continue
        except review_client.ReviewApiError:
            return
        _remember(trigger, payload, db)


def _trigger_summary(t: Trigger) -> dict[str, Any]:
    return {
        "trigger_id": t.id,
        "repo_url": t.repo_url,
        "branch": t.branch,
        "mode": t.mode,
        "review_id": t.review_id,
        "created_at": _iso(t.created_at),
        "status": t.status,
        "percent": t.percent,
        "units_done": t.units_done,
        "units_total": t.units_total,
        "commit": t.commit_sha,
        "model": t.model,
        "error": t.last_error,
        "paused_at": _iso(t.paused_at),
        "finished_at": _iso(t.finished_at),
        "status_updated_at": _iso(t.status_updated_at),
    }


def _cached_status(t: Trigger) -> dict[str, Any]:
    """A status payload built from the trigger alone, marked as such."""
    return {
        "review_id": t.review_id,
        "status": t.status,
        "percent": t.percent,
        "done": t.units_done,
        "total": t.units_total,
        "restored_units": 0,
        "commit": t.commit_sha,
        "error": t.last_error,
        "paused_at": _iso(t.paused_at),
        "finished_at": _iso(t.finished_at),
        "resumable": t.status in ("paused", "failed", "cancelled", "interrupted"),
        "restartable": t.status in ("paused", "failed", "cancelled", "interrupted"),
        "pausable": False,
        "source": "gateway",
    }


@app.post("/reviews/{trigger_id}/restart")
def restart_review(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Resume a failed review from its checkpoint.

    Without this, a review that dies partway through is unrecoverable
    THROUGH THE PRODUCT: starting again from the dashboard mints a new
    review_id, and review-api's checkpoint is keyed by the old one, so
    every finished file is re-reviewed from scratch. We watched a review
    fail at file 79 of 123 after fourteen hours - the checkpoint existed
    the whole time and there was simply no way to reach it.

    The signed-in user's token is forwarded for the same reason as when
    starting: a restart re-clones the repository, so a private repo fails
    at the clone without it.

    Authorization is _trigger_readable_by, the same rule as reading and
    deleting.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)

    try:
        result = review_client.restart_review(
            trigger.review_id,
            access_token=session.github_access_token if session else "",
        )
    except review_client.ReviewNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewStillRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "status": "restarted",
        "trigger_id": trigger_id,
        # How many finished units the checkpoint gave back. 0 here means
        # the restart is really starting over, which is worth surfacing
        # rather than quietly letting the user assume otherwise.
        "restored_units": result.get("restored_units"),
    }


@app.delete("/reviews/{trigger_id}")
def delete_review(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Delete a review completely. IRREVERSIBLE: the report, the resume
    checkpoint, the scan results and this trigger row all go.

    A running review is paused first (pausing stops its Job at once), so
    "delete" works from any state. Authorization is _trigger_readable_by,
    the same rule as reading it.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)
    if trigger.status in _LIVE or trigger.status is None:
        try:
            review_client.pause_review(trigger.review_id)
        except (review_client.ReviewNotFound, review_client.ReviewStillRunning):
            pass        # already stopped, or nothing to stop
        except review_client.ReviewApiError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    try:
        result = review_client.delete_review(trigger.review_id)
    except review_client.ReviewNotFound:
        result = {"removed": []}      # nothing stored; the row still goes
    except review_client.ReviewStillRunning as exc:
        raise HTTPException(
            status_code=409,
            detail="The review is still stopping. Try deleting it again in "
                   "a moment.") from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.delete(trigger)
    db.commit()
    log.info("review %s deleted", trigger.review_id)
    return {"status": "deleted", "trigger_id": trigger_id,
            "removed": result.get("removed", [])}


@app.delete("/reviews/{trigger_id}/report")
def delete_review_report(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Delete the stored report for a review. IRREVERSIBLE.

    Authorization is _trigger_readable_by - deliberately the SAME rule as
    reading, not a second one written for deletion. Two rules guarding one
    resource drift apart over time, and the weaker one silently becomes
    the real one. So: a review started while signed in is deletable only
    by that user; an anonymous one by whoever holds its unguessable
    trigger_id, which is the same credential that lets them read it.

    The Trigger row itself is KEPT. It is metadata the history view needs
    ("you ran this, on that repo, then"), it contains no report content,
    and removing it would leave a user unable to see that the review ever
    happened. Only review-api's stored artifacts go.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)

    try:
        result = review_client.delete_review_report(trigger.review_id)
    except review_client.ReviewNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewStillRunning as exc:
        # 409, not 502: review-api is fine and said no for a good reason.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"status": "deleted", "trigger_id": trigger_id, **result}


@app.get("/reviews/{trigger_id}/files")
def get_review_files(
    trigger_id: str,
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """Per-file progress for a live review: done / failed / running / pending.

    Goes through `_trigger_readable_by` like every other review endpoint.
    That matters more here than it looks: for a PRIVATE repository the list
    of file paths is itself information about the repository, even without
    any file's contents, so this is owner-only for exactly the same reason
    the report is.
    """
    trigger = _trigger_readable_by(trigger_id, session, db)

    try:
        return review_client.get_review_files(trigger.review_id)
    except review_client.ReviewNotFound as exc:
        # Usually "the review hasn't finished cloning yet" - the polling UI
        # retries rather than treating it as a dead end.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/reviews/{trigger_id}/report")
def get_review_report(
    trigger_id: str,
    view: str = "full",
    db: Session = Depends(get_db),
    session: AuthSession | None = Depends(get_current_session_optional),
):
    """view=full (default) is every issue's real detail - severity, line,
    description, suggested fix. view=summary is just file names + issue
    counts; view=markdown is the human-readable .md render."""
    trigger = _trigger_readable_by(trigger_id, session, db)

    try:
        report = review_client.get_review_report(trigger.review_id, view=view)
    except review_client.ReviewNotFound as exc:
        # Most often "not finished yet" - a real 404, not a gateway/review-api
        # failure, so the client (our own polling UI) can just try again.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_client.ReviewApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # view=markdown is plain text, not JSON - returning it as a bare str
    # would make FastAPI JSON-encode it (quoted, \n-escaped), and the
    # frontend's res.text() expects the raw markdown, not a JSON string.
    if view == "markdown":
        return PlainTextResponse(report, media_type="text/markdown")
    return report


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
