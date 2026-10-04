"""Site-wide settings: who the admins are, and which AI service runs reviews.

Admins. A list of GitHub usernames (or "id:<numeric id>") read from a FILE
on every check, cached by its modification time. In the cluster that file
is a ConfigMap mounted as a volume, so

    kubectl -n ai-scan-repos edit configmap gateway-admins

changes who is an admin within about a minute (the kubelet's sync period),
with no restart and nothing in the database. GATEWAY_ADMINS adds names from
the environment for local development. A username can be given up and then
registered by someone else, so the numeric id form is the stricter choice.

The AI service. One row in site_settings: the preset name, the address
(only for the "local" preset), the model, and the API key, which is stored
ONLY encrypted with Fernet under a key derived from GATEWAY_SETTINGS_KEY.
The key never leaves the server again after it is saved: reads return its
last four characters, and it is decrypted only to be forwarded to
review-api with a review, or to test the service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import settings
from .db import AuthSession, SiteSetting

log = logging.getLogger("review_gateway.site_settings")

AI = "ai"

_admin_cache: dict[str, Any] = {"mtime": None, "path": None, "names": set()}


def _parse_admins(text: str) -> set[str]:
    names = set()
    for item in re.split(r"[\s,]+", text or ""):
        item = item.strip().lstrip("@").lower()
        if item and not item.startswith("#"):
            names.add(item)
    return names


def admin_names() -> set[str]:
    """Everyone listed as an admin, lowercased."""
    path = settings.admins_file
    names: set[str] = set()
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        mtime = None
    if mtime is not None:
        if _admin_cache["path"] != path or _admin_cache["mtime"] != mtime:
            try:
                with open(path, encoding="utf-8") as fh:
                    text = "\n".join(line.split("#", 1)[0] for line in fh)
                _admin_cache.update(path=path, mtime=mtime,
                                    names=_parse_admins(text))
            except OSError:
                _admin_cache.update(path=path, mtime=None, names=set())
        names |= _admin_cache["names"]
    return names | _parse_admins(settings.admins)


def is_admin(session: AuthSession | None) -> bool:
    if session is None:
        return False
    names = admin_names()
    return (session.github_login.lower() in names
            or f"id:{session.github_user_id}" in names)


# --- encryption ---------------------------------------------------------------

class SettingsKeyMissing(RuntimeError):
    """GATEWAY_SETTINGS_KEY is not set, so no API key can be stored."""


class SettingsKeyChanged(RuntimeError):
    """The stored API key was encrypted under a different key."""


def _fernet() -> Fernet:
    secret = settings.settings_encryption_key
    if not secret:
        raise SettingsKeyMissing(
            "This server has no GATEWAY_SETTINGS_KEY, so it cannot store an "
            "API key. Ask whoever runs it to add one (see DEPLOY-K3S.md).")
    # Any string works as the setting; Fernet needs exactly 32 url-safe
    # base64 bytes, so derive them.
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encryption_ready() -> bool:
    return bool(settings.settings_encryption_key)


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise SettingsKeyChanged(
            "The saved API key can't be read: GATEWAY_SETTINGS_KEY changed "
            "since it was saved. An admin must enter the key again in "
            "Settings.") from exc


def _hint(key: str) -> str:
    return f"…{key[-4:]}" if len(key) >= 8 else "…"


# --- the AI service row -------------------------------------------------------

def _row(db: Session) -> SiteSetting | None:
    return db.get(SiteSetting, AI)


def ai_public(db: Session) -> dict[str, Any]:
    """The AI choice as anyone signed in may see it. Never the key."""
    row = _row(db)
    if row is None:
        return {"configured": False}
    value = json.loads(row.value or "{}")
    return {"configured": True,
            "preset": value.get("preset"),
            "endpoint": value.get("endpoint") or None,
            "model": value.get("model") or None,
            "key_saved": bool(row.secret_enc),
            "key_hint": row.secret_hint if row.secret_enc else None,
            "updated_by": row.updated_by,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None}


def save_ai(db: Session, *, preset: str, endpoint: str, model: str,
            api_key: str | None, clear_key: bool, who: str) -> dict[str, Any]:
    """Store the choice. api_key None or "" keeps the saved key unless the
    preset changed (a key belongs to one service) or clear_key is set."""
    row = _row(db)
    old = json.loads(row.value) if row else {}
    if row is None:
        row = SiteSetting(name=AI)
        db.add(row)
    if api_key:
        row.secret_enc = _encrypt(api_key)
        row.secret_hint = _hint(api_key)
    elif clear_key or old.get("preset") != preset:
        row.secret_enc = row.secret_hint = None
    row.value = json.dumps({"preset": preset, "endpoint": endpoint,
                            "model": model})
    row.updated_by = who
    db.commit()
    db.refresh(row)
    return ai_public(db)


def clear_ai(db: Session) -> None:
    row = _row(db)
    if row is not None:
        db.delete(row)
        db.commit()


def ai_for_review(db: Session) -> dict[str, str] | None:
    """The `llm` object review-api takes, key decrypted; None when no AI
    service was chosen (review-api's own default then applies).
    Raises SettingsKeyChanged / SettingsKeyMissing when the key can't be
    read, so a review fails at the start with a reason, not ten minutes in
    with a 401."""
    row = _row(db)
    if row is None:
        return None
    value = json.loads(row.value or "{}")
    llm = {"preset": value.get("preset") or "", "endpoint": value.get("endpoint") or "",
           "model": value.get("model") or ""}
    if row.secret_enc:
        llm["api_key"] = _decrypt(row.secret_enc)
    return llm


def saved_key_for(db: Session, preset: str) -> str:
    """The saved key, for testing the SAME service without retyping it."""
    row = _row(db)
    if row is None or not row.secret_enc:
        return ""
    if json.loads(row.value or "{}").get("preset") != preset:
        return ""
    return _decrypt(row.secret_enc)
