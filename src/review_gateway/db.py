"""Three tables:

Trigger    - a thin map from "a GitHub event happened" to "which review-api
             job is handling it". review-api owns the actual review state
             (progress, report, retries); the trigger keeps only the LAST
             STATUS it saw, so "my reviews" can say paused / failed /
             completed days later without asking review-api about every row,
             and still knows what to resume after review-api forgot.
AuthSession - a logged-in user. The browser only ever holds this row's id
             (an opaque token, in an HttpOnly cookie) - the GitHub access
             token itself never leaves the server. See github_oauth.py.
UserSettings - one row of preferences per GitHub account, keyed by the
             numeric GitHub user id (stable across logins and renames).
SiteSetting - settings for the whole site, changed by admins. Today one
             row, "ai": which AI service every review uses.
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


class Trigger(Base):
    __tablename__ = "triggers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    github_event: Mapped[str] = mapped_column(String(32))
    repo_url: Mapped[str] = mapped_column(String(512))
    branch: Mapped[str] = mapped_column(String(255), default="")
    mode: Mapped[str] = mapped_column(String(16), default="brief")
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_id: Mapped[str] = mapped_column(String(64))
    # Null for webhook-triggered reviews (no browser session exists) and for
    # manual reviews started while logged out (quick/brief don't require
    # login). Only set when we actually know who asked - see
    # _start_and_record_review in app.py. This is what "my history" filters on.
    github_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # --- last known state, cached from review-api (added 2026-10-01) -------
    # Every column below is nullable and filled in as statuses are seen, so
    # rows written before they existed simply read as "not known yet".
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Overall progress against the WHOLE review, restored units included.
    percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    units_done: Mapped[int | None] = mapped_column(Integer, nullable=True)
    units_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class UserSettings(Base):
    """Preferences that follow a person, not a browser: sign in on another
    machine two days later and the site looks and behaves the same."""

    __tablename__ = "user_settings"

    github_user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # JSON object; validated by the route that writes it (app.py), so the
    # column itself stays schema-free and a new preference needs no migration.
    prefs: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc))

    def load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.prefs or "{}")
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}


class SiteSetting(Base):
    """One site-wide setting. The AI service row holds the API key ONLY
    encrypted (site_settings.py), plus its last four characters so an admin
    can tell which key is saved without the key ever being shown again."""

    __tablename__ = "site_settings"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    # JSON object of the non-secret values (preset, endpoint, model).
    value: Mapped[str] = mapped_column(Text, default="{}")
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_hint: Mapped[str | None] = mapped_column(String(16), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc))


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    # An opaque, unguessable token (not a database auto-increment id) - this
    # is the value stored in the browser's cookie, so it has to be
    # unpredictable on its own, not just "hard to enumerate".
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: secrets.token_urlsafe(32)
    )
    github_user_id: Mapped[int] = mapped_column(Integer)
    github_login: Mapped[str] = mapped_column(String(255))
    # The user's GitHub access token. Stays server-side always - see
    # AuthSession's docstring above. Real deployment should encrypt this
    # column at rest; out of scope for the skeleton.
    github_access_token: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    @staticmethod
    def new_expiry() -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=settings.session_ttl_seconds)

    def is_expired(self) -> bool:
        expires_at = self.expires_at
        if expires_at.tzinfo is None:  # SQLite drops tzinfo on round-trip
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires_at


def _make_engine(url: str):
    """The one engine the gateway uses, and why each option is set.

    pool_pre_ping: check a pooled connection is alive before handing it out.
    Without it, restarting Postgres - a Pod deletion, a node reboot, an RDS
    failover - left every idle pooled connection pointing at the old server
    process, and the next request to use one failed with a 500
    (psycopg AdminShutdown). Found on 2026-09-30, right after deleting the
    Postgres Pod in an acceptance test.

    hide_parameters: keep bound values out of error messages. SQLAlchemy
    otherwise prints them with the failing SQL, and the gateway's queries
    bind session ids and GitHub access tokens - that same 500 wrote a live
    session id into the Pod log, where anyone reading logs could reuse it.
    """
    return create_engine(
        url,
        connect_args=({"check_same_thread": False}
                      if url.startswith("sqlite") else {}),
        pool_pre_ping=True,
        hide_parameters=True,
    )


_engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


log = logging.getLogger("review_gateway.db")


def _add_missing_columns(engine) -> list[str]:
    """Add columns the models have and an existing table lacks.

    create_all() creates missing TABLES but never alters an existing one,
    and the deployed Postgres already has `triggers` from before the status
    columns existed. Every added column is nullable, so ADD COLUMN is safe
    on a table with rows, and running this twice is a no-op. Additive only:
    nothing is ever dropped or retyped here.
    """
    added: list[str] = []
    existing_tables = set(inspect(engine).get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            have = {c["name"] for c in inspect(conn).get_columns(table.name)}
            for column in table.columns:
                if column.name in have or not column.nullable:
                    continue
                ddl_type = column.type.compile(dialect=engine.dialect)
                conn.execute(text(
                    f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {ddl_type}'))
                added.append(f"{table.name}.{column.name}")
    if added:
        log.info("database: added columns %s", ", ".join(added))
    return added


def init_db() -> None:
    Base.metadata.create_all(_engine)
    _add_missing_columns(_engine)


def get_session() -> Session:
    return SessionLocal()
