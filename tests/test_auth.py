from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from review_gateway import review_client
from review_gateway.app import app
from review_gateway.db import AuthSession, get_session
from review_gateway.github_oauth import GitHubOAuthError


@pytest.fixture
def client():
    return TestClient(app)


def test_login_redirects_to_github_with_state(client):
    resp = client.get("/auth/github/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize")
    assert "client_id=" in location
    assert "state=" in location
    assert "oauth_state" in resp.cookies


def test_callback_rejects_missing_state(client):
    resp = client.get("/auth/github/callback", params={"code": "abc"})
    assert resp.status_code == 400


def test_callback_rejects_mismatched_state(client):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    real_state = login_resp.cookies["oauth_state"]
    resp = client.get(
        "/auth/github/callback", params={"code": "abc", "state": "wrong-" + real_state}
    )
    assert resp.status_code == 400


def test_callback_success_creates_session_and_sets_cookie(client):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    state = login_resp.cookies["oauth_state"]

    with (
        patch(
            "review_gateway.app.github_oauth.exchange_code_for_token",
            return_value="gh-token-123",
        ) as mock_exchange,
        patch(
            "review_gateway.app.github_oauth.fetch_github_user",
            return_value={"id": 42, "login": "octocat"},
        ),
    ):
        resp = client.get(
            "/auth/github/callback",
            params={"code": "abc123", "state": state},
            follow_redirects=False,
        )

    # Sends the browser back to the app, not a raw JSON page on the
    # gateway's own origin.
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "http://localhost:5173"
    assert "session_id" in resp.cookies
    mock_exchange.assert_called_once_with("abc123")


def test_callback_propagates_github_errors_as_502(client):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    state = login_resp.cookies["oauth_state"]

    with patch(
        "review_gateway.app.github_oauth.exchange_code_for_token",
        side_effect=GitHubOAuthError("GitHub is unreachable"),
    ):
        resp = client.get("/auth/github/callback", params={"code": "abc", "state": state})

    assert resp.status_code == 502


def test_me_without_session_is_401(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_me_after_login_returns_the_user(client):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    state = login_resp.cookies["oauth_state"]

    with (
        patch(
            "review_gateway.app.github_oauth.exchange_code_for_token",
            return_value="gh-token-123",
        ),
        patch(
            "review_gateway.app.github_oauth.fetch_github_user",
            return_value={"id": 42, "login": "octocat"},
        ),
    ):
        client.get(
            "/auth/github/callback",
            params={"code": "abc", "state": state},
            follow_redirects=False,
        )

    resp = client.get("/auth/me")
    assert resp.status_code == 200
    me = resp.json()
    assert (me["login"], me["github_user_id"]) == ("octocat", 42)
    # From the numeric id, so a renamed account keeps its picture.
    assert me["avatar_url"].startswith("https://avatars.githubusercontent.com/u/42")
    assert me["session_expires_at"]
    assert "gh-token-123" not in resp.text


def test_me_with_expired_session_is_401(client):
    db = get_session()
    session = AuthSession(
        github_user_id=1,
        github_login="ghost",
        github_access_token="gh-old",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    session_id = session.id
    db.close()

    client.cookies.set("session_id", session_id)
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_logout_clears_the_session(client):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    state = login_resp.cookies["oauth_state"]
    with (
        patch(
            "review_gateway.app.github_oauth.exchange_code_for_token",
            return_value="gh-token-123",
        ),
        patch(
            "review_gateway.app.github_oauth.fetch_github_user",
            return_value={"id": 42, "login": "octocat"},
        ),
    ):
        client.get(
            "/auth/github/callback",
            params={"code": "abc", "state": state},
            follow_redirects=False,
        )

    assert client.get("/auth/me").status_code == 200

    logout_resp = client.post("/auth/logout")
    assert logout_resp.status_code == 200
    assert client.get("/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# Deep-mode gate on POST /reviews (ADR-006) - quick/brief stay open
# ---------------------------------------------------------------------------

def _log_in(client, login="octocat", user_id=42):
    login_resp = client.get("/auth/github/login", follow_redirects=False)
    state = login_resp.cookies["oauth_state"]
    with (
        patch(
            "review_gateway.app.github_oauth.exchange_code_for_token",
            return_value="gh-token-123",
        ),
        patch(
            "review_gateway.app.github_oauth.fetch_github_user",
            return_value={"id": user_id, "login": login},
        ),
    ):
        client.get(
            "/auth/github/callback",
            params={"code": "abc", "state": state},
            follow_redirects=False,
        )


def test_deep_review_without_login_is_401(client):
    resp = client.post(
        "/reviews",
        json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "deep"},
    )
    assert resp.status_code == 401


def test_deep_review_logged_in_without_repo_access_is_403(client):
    _log_in(client)
    with patch("review_gateway.app.github_oauth.check_repo_permission", return_value="none"):
        resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "deep"},
        )
    assert resp.status_code == 403


def test_deep_review_logged_in_with_repo_access_succeeds(client):
    _log_in(client)
    with (
        patch("review_gateway.app.github_oauth.check_repo_permission", return_value="read") as mock_perm,
        patch(
            "review_gateway.app.review_client.start_review",
            return_value={"review_id": "gw-deep001", "status": "requested"},
        ),
    ):
        resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "deep"},
        )
    assert resp.status_code == 200
    mock_perm.assert_called_once_with("gh-token-123", "octocat", "Hello-World", "octocat")


def test_brief_review_without_login_still_works(client):
    """Only deep is gated - quick/brief match the anonymous Summary Report tier."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-brief001", "status": "requested"},
    ):
        resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    assert resp.status_code == 200


def test_deep_review_bad_host_is_400_not_401(client):
    """Host validation happens before the login check - no point asking
    someone to log in for a URL we're going to reject anyway."""
    resp = client.post(
        "/reviews", json={"repo_url": "https://evil.com/x/y.git", "mode": "deep"}
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /reviews (my history)
# ---------------------------------------------------------------------------

def test_list_my_reviews_without_login_is_401(client):
    resp = client.get("/reviews")
    assert resp.status_code == 401


def test_list_my_reviews_returns_my_own_trigger(client):
    # Unique user_id - other tests in this file also log in as user_id=42
    # against the same shared test DB (see conftest.py), so reusing it here
    # would pick up their triggers too.
    _log_in(client, login="history-user-1", user_id=90001)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-hist001", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.get_review_status",
        return_value={"review_id": "gw-hist001", "status": "reviewing",
                      "done": 3, "total": 10, "restored_units": 0},
    ):
        resp = client.get("/reviews")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert {k: data[0][k] for k in ("trigger_id", "repo_url", "branch", "mode",
                                    "review_id", "status", "percent")} == {
        "trigger_id": trigger_id,
        "repo_url": "https://github.com/octocat/Hello-World.git",
        "branch": "",
        "mode": "brief",
        "review_id": "gw-hist001",
        # Refreshed from review-api because the review was still live.
        "status": "reviewing",
        "percent": 30,
    }


def test_list_my_reviews_excludes_reviews_started_while_logged_out(client):
    """No github_user_id was captured for this one (see
    _start_and_record_review) - it must never show up in anyone's history."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-anon001", "status": "requested"},
    ):
        client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )

    _log_in(client, login="history-user-2", user_id=90002)
    resp = client.get("/reviews")
    assert resp.status_code == 200
    assert resp.json() == []


def test_signed_in_user_token_is_forwarded_for_the_clone(client):
    """Without this, a signed-in user with real access to a private repo
    still got "could not read Username for github.com" - the gateway held
    their token but never passed it on."""
    _log_in(client, login="token-user", user_id=92001)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-token001", "status": "requested"},
    ) as mock_start:
        client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    assert mock_start.call_args.kwargs["access_token"] == "gh-token-123"


def test_anonymous_review_forwards_no_token(client):
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-token002", "status": "requested"},
    ) as mock_start:
        client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    assert mock_start.call_args.kwargs["access_token"] == ""


def test_token_travels_in_a_header_not_the_request_body(monkeypatch):
    """A token in the JSON body would land in any log that records request
    payloads. Pin it to the header so that can't regress."""
    from review_gateway import review_client

    captured = {}

    class _FakeResponse:
        status_code = 202

        @staticmethod
        def json():
            return {"review_id": "gw-hdr001", "status": "requested"}

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, _url, json=None, headers=None):
            captured["json"] = json
            captured["headers"] = headers
            return _FakeResponse()

    monkeypatch.setattr(review_client.httpx, "Client", _FakeClient)
    review_client.start_review(
        repo_url="https://github.com/o/r.git",
        branch="main",
        files=None,
        access_token="gh-secret-token",
    )

    assert captured["headers"]["X-Repo-Token"] == "gh-secret-token"
    assert "gh-secret-token" not in str(captured["json"])


def test_restart_forwards_the_owner_token(client):
    """The bug this endpoint exists to prevent: restarting re-clones the
    repository, so without the signed-in user's token a private repo
    fails at the clone - exactly how a real 14-hour review's resume
    failed before this existed."""
    _log_in(client, login="resume-owner", user_id=94001)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-res001", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.restart_review",
        return_value={"action": "restarted", "restored_units": 79},
    ) as mock_restart:
        resp = client.post(f"/reviews/{trigger_id}/restart")

    assert resp.status_code == 200
    assert resp.json()["restored_units"] == 79
    mock_restart.assert_called_once_with("gw-res001", access_token="gh-token-123")


def test_another_user_cannot_restart_my_review(client):
    _log_in(client, login="resume-owner-2", user_id=94002)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-res002", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    attacker = TestClient(app)
    _log_in(attacker, login="resume-attacker", user_id=94003)
    with patch("review_gateway.app.review_client.restart_review") as mock_restart:
        resp = attacker.post(f"/reviews/{trigger_id}/restart")

    assert resp.status_code == 404
    mock_restart.assert_not_called()


def test_restarting_a_running_review_is_409(client):
    _log_in(client, login="resume-owner-3", user_id=94004)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-res003", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.restart_review",
        side_effect=review_client.ReviewStillRunning("nothing to resume"),
    ):
        resp = client.post(f"/reviews/{trigger_id}/restart")

    assert resp.status_code == 409


def test_another_user_cannot_delete_my_report(client):
    """Deletion reuses the read rule on purpose. If it ever grows its own
    weaker rule, this is what catches it."""
    _log_in(client, login="del-owner", user_id=93001)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-del001", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    attacker = TestClient(app)
    _log_in(attacker, login="del-attacker", user_id=93002)
    with patch("review_gateway.app.review_client.delete_review_report") as mock_delete:
        resp = attacker.delete(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 404
    # The point: review-api was never even asked.
    mock_delete.assert_not_called()


def test_owner_can_delete_their_own_report(client):
    _log_in(client, login="del-owner-2", user_id=93003)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-del002", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.delete_review_report",
        return_value={"action": "deleted", "deleted": ["gw-del002.json", "gw-del002.md"]},
    ) as mock_delete:
        resp = client.delete(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"
    mock_delete.assert_called_once_with("gw-del002")


def test_deleting_a_running_review_is_409_not_502(client):
    """review-api refusing because the report is still being written is a
    normal answer, not an upstream failure."""
    _log_in(client, login="del-owner-3", user_id=93004)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-del003", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.delete_review_report",
        side_effect=review_client.ReviewStillRunning("still reviewing"),
    ):
        resp = client.delete(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 409


def test_anonymous_review_report_is_deletable_by_trigger_id(client):
    """No owner to check against, so holding the unguessable id is the
    credential - same as reading it."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-del004", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    other = TestClient(app)
    with patch(
        "review_gateway.app.review_client.delete_review_report",
        return_value={"action": "deleted", "deleted": ["gw-del004.json"]},
    ):
        resp = other.delete(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 200


def test_another_user_cannot_read_my_review_status(client):
    """The hole this closes: before, ANY caller holding a trigger_id could
    read ANY review - including a deep review on a private repo."""
    _log_in(client, login="owner-user", user_id=91001)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-owned001", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    attacker = TestClient(app)
    _log_in(attacker, login="attacker-user", user_id=91002)
    # 404, not 403 - the endpoint must not confirm that this id exists.
    assert attacker.get(f"/reviews/{trigger_id}").status_code == 404
    assert attacker.get(f"/reviews/{trigger_id}/report").status_code == 404


def test_logged_out_caller_cannot_read_an_owned_review(client):
    _log_in(client, login="owner-user-2", user_id=91003)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-owned002", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    anonymous = TestClient(app)
    assert anonymous.get(f"/reviews/{trigger_id}").status_code == 404
    assert anonymous.get(f"/reviews/{trigger_id}/report").status_code == 404


def test_owner_can_still_read_their_own_review(client):
    """The gate must not lock the owner out of their own review."""
    _log_in(client, login="owner-user-3", user_id=91004)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-owned003", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.get_review_status",
        return_value={"review_id": "gw-owned003", "status": "reviewing"},
    ):
        resp = client.get(f"/reviews/{trigger_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reviewing"


def test_anonymous_review_stays_readable_by_trigger_id(client):
    """quick/brief without login have no owner to compare against, so the
    unguessable trigger_id IS the credential - this must keep working."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-anon002", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    other = TestClient(app)
    with patch(
        "review_gateway.app.review_client.get_review_status",
        return_value={"review_id": "gw-anon002", "status": "reviewing"},
    ):
        resp = other.get(f"/reviews/{trigger_id}")
    assert resp.status_code == 200


def test_list_my_reviews_does_not_leak_other_users_reviews(client):
    _log_in(client, login="history-user-3", user_id=90003)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-mine001", "status": "requested"},
    ):
        client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )

    other_client = TestClient(app)
    _log_in(other_client, login="history-user-4", user_id=90004)
    resp = other_client.get("/reviews")
    assert resp.status_code == 200
    assert resp.json() == []


def test_another_user_cannot_list_my_reviewed_files(client):
    """File paths of a PRIVATE repository are information about that
    repository even with no contents attached, so the progress view is
    owner-only exactly like the report.

    Started as `brief` like the sibling tests: `deep` would call the real
    GitHub access check, and the ownership gate being tested here does not
    depend on the mode.
    """
    _log_in(client, login="owner-user-4", user_id=91005)
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-owned004", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    attacker = TestClient(app)
    _log_in(attacker, login="attacker-user-2", user_id=91006)
    # 404, not 403 - same non-disclosing denial as the other endpoints.
    assert attacker.get(f"/reviews/{trigger_id}/files").status_code == 404
    assert TestClient(app).get(f"/reviews/{trigger_id}/files").status_code == 404
