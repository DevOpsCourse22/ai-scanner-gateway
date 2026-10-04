"""Pause, resume and "my reviews" days later - the gateway's half.

review-api does the pausing; the gateway's job is to let only the owner do
it, forward the CURRENT session's token on resume, and remember each
review's last status so the history still reads paused / failed /
completed after review-api has forgotten it.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from review_gateway import db as gateway_db
from review_gateway import review_client
from review_gateway.app import app

from test_auth import _log_in

REPO = "https://github.com/octocat/Hello-World"
SHA = "e" * 40


def _start(client, review_id, mode="brief", branch="main"):
    with patch("review_gateway.app.review_client.start_review",
               return_value={"review_id": review_id, "status": "requested"}):
        resp = client.post("/reviews", json={"repo_url": REPO, "mode": mode,
                                             "branch": branch})
    assert resp.status_code == 200
    return resp.json()["trigger_id"]


def test_owner_pauses_then_resumes_days_later_with_a_new_session():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner", user_id=95001)
    trigger_id = _start(owner, "gw-pause001")

    # The status poll teaches the gateway the commit being reviewed.
    with patch("review_gateway.app.review_client.get_review_status",
               return_value={"status": "reviewing", "done": 40, "total": 100,
                             "restored_units": 0, "commit": SHA}):
        assert owner.get(f"/reviews/{trigger_id}").json()["trigger"]["percent"] == 40

    with patch("review_gateway.app.review_client.pause_review",
               return_value={"status": "paused", "paused_at": "2026-10-01T10:00:00Z",
                             "done": 41, "total": 100}) as pause:
        resp = owner.post(f"/reviews/{trigger_id}/pause")
    assert resp.status_code == 200
    pause.assert_called_once_with("gw-pause001")
    assert resp.json()["trigger"]["status"] == "paused"

    # Two days later: signed out, signed in again - a NEW session and token.
    owner.post("/auth/logout")
    later = TestClient(app)
    with patch("review_gateway.app.github_oauth.exchange_code_for_token",
               return_value="gh-token-two-days-later"):
        login = later.get("/auth/github/login", follow_redirects=False)
        with patch("review_gateway.app.github_oauth.fetch_github_user",
                   return_value={"id": 95001, "login": "pause-owner"}):
            later.get("/auth/github/callback",
                      params={"code": "c", "state": login.cookies["oauth_state"]},
                      follow_redirects=False)

    # review-api is not asked: a paused review cannot have moved.
    with patch("review_gateway.app.review_client.get_review_status") as status:
        rows = later.get("/reviews").json()
    status.assert_not_called()
    (row,) = [r for r in rows if r["trigger_id"] == trigger_id]
    assert (row["status"], row["percent"], row["commit"]) == ("paused", 41, SHA)
    assert row["paused_at"].startswith("2026-10-01T10:00:00")

    with patch("review_gateway.app.review_client.resume_review",
               return_value={"status": "cloning", "action": "resumed",
                             "restored_units": 41}) as resume:
        resp = later.post(f"/reviews/{trigger_id}/resume")
    assert resp.status_code == 200
    resume.assert_called_once_with(
        "gw-pause001", repo_url=REPO, branch="main", mode="brief",
        commit=SHA, access_token="gh-token-two-days-later", llm=None)
    assert resp.json()["trigger"]["status"] == "cloning"
    assert resp.json()["trigger"]["paused_at"] is None


def test_another_user_can_neither_pause_nor_resume_my_review():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-2", user_id=95002)
    trigger_id = _start(owner, "gw-pause002")
    attacker = TestClient(app)
    _log_in(attacker, login="pause-attacker", user_id=95003)
    with (patch("review_gateway.app.review_client.pause_review") as pause,
          patch("review_gateway.app.review_client.resume_review") as resume):
        assert attacker.post(f"/reviews/{trigger_id}/pause").status_code == 404
        assert attacker.post(f"/reviews/{trigger_id}/resume").status_code == 404
    pause.assert_not_called()
    resume.assert_not_called()


def test_resume_while_another_review_runs_is_409_with_a_clear_reason():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-4", user_id=95004)
    trigger_id = _start(owner, "gw-pause004")
    with patch("review_gateway.app.review_client.resume_review",
               side_effect=review_client.ReviewApiBusy("Another review is running")):
        resp = owner.post(f"/reviews/{trigger_id}/resume")
    assert resp.status_code == 409
    assert "Another review" in resp.json()["detail"]


def test_pausing_a_finished_review_is_409():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-5", user_id=95005)
    trigger_id = _start(owner, "gw-pause005")
    with patch("review_gateway.app.review_client.pause_review",
               side_effect=review_client.ReviewStillRunning("Nothing to pause")):
        assert owner.post(f"/reviews/{trigger_id}/pause").status_code == 409


def test_a_review_api_that_forgot_still_gets_the_last_known_status():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-6", user_id=95006)
    trigger_id = _start(owner, "gw-pause006")
    with patch("review_gateway.app.review_client.get_review_status",
               return_value={"status": "failed", "error": "LLM unreachable",
                             "done": 5, "total": 9, "restored_units": 0}):
        owner.get(f"/reviews/{trigger_id}")
    with patch("review_gateway.app.review_client.get_review_status",
               side_effect=review_client.ReviewNotFound("gone")):
        body = owner.get(f"/reviews/{trigger_id}").json()
    assert body["status"] == "failed" and body["source"] == "gateway"
    assert body["error"] == "LLM unreachable" and body["resumable"] is True


def test_a_deep_resume_rechecks_repository_access():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-7", user_id=95007)
    with patch("review_gateway.app.github_oauth.check_repo_permission",
               return_value="read"):
        trigger_id = _start(owner, "gw-pause007", mode="deep")
    with (patch("review_gateway.app.github_oauth.check_repo_permission",
                return_value="none"),
          patch("review_gateway.app.review_client.resume_review") as resume):
        assert owner.post(f"/reviews/{trigger_id}/resume").status_code == 403
    resume.assert_not_called()


def test_the_list_still_loads_when_review_api_is_down():
    owner = TestClient(app)
    _log_in(owner, login="pause-owner-8", user_id=95008)
    _start(owner, "gw-pause008")
    _start(owner, "gw-pause009")
    with patch("review_gateway.app.review_client.get_review_status",
               side_effect=review_client.ReviewApiError("down")) as status:
        resp = owner.get("/reviews")
    assert resp.status_code == 200 and len(resp.json()) == 2
    assert status.call_count == 1                   # gave up after the first


# ---------------- settings ----------------

def test_settings_default_then_persist_per_github_account():
    one = TestClient(app)
    _log_in(one, login="settings-user", user_id=96001)
    assert one.get("/auth/me/settings").json() == {
        "theme": "system", "motion": "system", "default_mode": "brief",
        "default_branch": "", "confirm_pause": True}
    saved = {"theme": "dark", "motion": "reduce", "default_mode": "deep",
             "default_branch": "develop", "confirm_pause": False}
    assert one.put("/auth/me/settings", json=saved).json() == saved

    # Another browser, another login of the same GitHub account.
    two = TestClient(app)
    _log_in(two, login="settings-user", user_id=96001)
    assert two.get("/auth/me/settings").json() == saved
    # ...and nobody else's.
    other = TestClient(app)
    _log_in(other, login="someone-else", user_id=96002)
    assert other.get("/auth/me/settings").json()["theme"] == "system"


def test_settings_need_login_and_refuse_unknown_values():
    anonymous = TestClient(app)
    assert anonymous.get("/auth/me/settings").status_code == 401
    user = TestClient(app)
    _log_in(user, login="settings-user-3", user_id=96003)
    assert user.put("/auth/me/settings", json={"theme": "neon"}).status_code == 422
    assert user.put("/auth/me/settings", json={"colour": "red"}).status_code == 422


# ---------------- the deployed database gets the new columns ----------------

def test_an_existing_triggers_table_gets_the_new_columns(tmp_path):
    """The Postgres on K3s already has `triggers` from before the status
    columns. create_all() never alters a table, so without this the first
    query after the upgrade would fail on a missing column."""
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE triggers (id VARCHAR(36) PRIMARY KEY, "
            "github_event VARCHAR(32), repo_url VARCHAR(512), branch VARCHAR(255), "
            "mode VARCHAR(16), commit_sha VARCHAR(64), review_id VARCHAR(64), "
            "github_user_id INTEGER, created_at DATETIME)"))
        conn.execute(text(
            "INSERT INTO triggers (id, github_event, repo_url, branch, mode, "
            "review_id) VALUES ('t1', 'manual', 'r', '', 'brief', 'gw-1')"))
    gateway_db.Base.metadata.create_all(engine)
    added = gateway_db._add_missing_columns(engine)
    assert "triggers.status" in added and "triggers.paused_at" in added
    columns = {c["name"] for c in inspect(engine).get_columns("triggers")}
    assert {"status", "percent", "paused_at", "finished_at"} <= columns
    with engine.connect() as conn:                  # the old row survived
        assert conn.execute(text("SELECT review_id FROM triggers")).scalar() == "gw-1"
    assert gateway_db._add_missing_columns(engine) == []   # idempotent
