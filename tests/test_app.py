import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from review_gateway import github_auth, review_client
from review_gateway.app import app
from review_gateway.review_client import ReviewApiBusy, ReviewApiError, ReviewNotFound

SECRET = "test-secret"


def sign(body: bytes, secret: str = SECRET) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# github_auth unit tests
# ---------------------------------------------------------------------------

def test_signature_accepts_valid_hmac():
    body = b'{"zen":"hello"}'
    assert github_auth.verify_github_signature(body, sign(body), SECRET) is True


def test_signature_rejects_tampered_body():
    body = b'{"zen":"hello"}'
    tampered = b'{"zen":"goodbye"}'
    assert github_auth.verify_github_signature(tampered, sign(body), SECRET) is False


def test_signature_rejects_when_secret_empty():
    body = b"data"
    assert github_auth.verify_github_signature(body, sign(body), "") is False


def test_validate_repo_url_accepts_github():
    github_auth.validate_repo_url("https://github.com/octocat/Hello-World.git")  # no raise


def test_validate_repo_url_rejects_other_host():
    with pytest.raises(ValueError):
        github_auth.validate_repo_url("https://evil.com/x/y.git")


def test_extract_trigger_info_push_collects_changed_files():
    payload = {
        "ref": "refs/heads/main",
        "after": "abc123",
        "repository": {"clone_url": "https://github.com/octocat/Hello-World.git"},
        "commits": [
            {"added": ["a.py"], "modified": ["b.py"]},
            {"added": [], "modified": ["a.py", "c.py"]},
        ],
    }
    info = github_auth.extract_trigger_info("push", payload)
    assert info.branch == "main"
    assert info.files == ["a.py", "b.py", "c.py"]
    assert info.commit_sha == "abc123"


def test_extract_trigger_info_ignores_unhandled_events():
    payload = {"repository": {"clone_url": "https://github.com/o/r.git"}}
    assert github_auth.extract_trigger_info("issues", payload) is None


# ---------------------------------------------------------------------------
# /webhook
# ---------------------------------------------------------------------------

def test_webhook_rejects_invalid_signature(client):
    resp = client.post(
        "/webhook",
        content=b'{"zen":"hello"}',
        headers={
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Event": "ping",
        },
    )
    assert resp.status_code == 401


def test_webhook_ping_returns_pong(client):
    body = json.dumps({"zen": "hello"}).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "ping"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"message": "pong"}


def test_webhook_ignores_unhandled_event_types(client):
    body = json.dumps({"zen": "hello"}).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "issues"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ignored", "event": "issues"}


def test_webhook_push_rejects_bad_host(client):
    payload = {"repository": {"clone_url": "https://evil.com/x/y.git"}, "ref": "refs/heads/main"}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "push"},
    )
    assert resp.status_code == 400


def test_webhook_push_calls_review_api_and_stores_trigger(client):
    payload = {
        "ref": "refs/heads/main",
        "after": "abc123",
        "repository": {"clone_url": "https://github.com/octocat/Hello-World.git"},
        "commits": [{"added": ["a.py"], "modified": []}],
    }
    body = json.dumps(payload).encode()

    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-fake0000001", "status": "requested"},
    ) as mock_start:
        resp = client.post(
            "/webhook",
            content=body,
            headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "push"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["review_id"] == "gw-fake0000001"
    assert "trigger_id" in data
    mock_start.assert_called_once_with(
        repo_url="https://github.com/octocat/Hello-World.git",
        branch="main",
        files=["a.py"],
        mode=None,
        # GitHub is a server, not a signed-in user - no token to forward.
        access_token="",
        # No scan has run for a webhook push - see scanner/README.md.
        findings_file=None,
        # A webhook expresses no provider preference: review-api uses its
        # own default, which is how this behaved before the choice existed.
        provider=None,
        # No AI service chosen in Settings: review-api's default applies.
        llm=None,
    )


def test_webhook_push_returns_502_when_review_api_unreachable(client):
    payload = {
        "ref": "refs/heads/main",
        "repository": {"clone_url": "https://github.com/octocat/Hello-World.git"},
        "commits": [],
    }
    body = json.dumps(payload).encode()

    with patch(
        "review_gateway.app.review_client.start_review",
        side_effect=ReviewApiError("Cannot reach review-api"),
    ):
        resp = client.post(
            "/webhook",
            content=body,
            headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "push"},
        )
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# /reviews/{trigger_id}
# ---------------------------------------------------------------------------

def test_get_review_unknown_trigger_returns_404(client):
    resp = client.get("/reviews/does-not-exist")
    assert resp.status_code == 404


def test_get_review_proxies_status(client):
    payload = {
        "ref": "refs/heads/main",
        "repository": {"clone_url": "https://github.com/octocat/Hello-World.git"},
        "commits": [],
    }
    body = json.dumps(payload).encode()
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-fake0000002", "status": "requested"},
    ):
        create_resp = client.post(
            "/webhook",
            content=body,
            headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "push"},
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.get_review_status",
        return_value={"review_id": "gw-fake0000002", "status": "reviewing"},
    ) as mock_status:
        resp = client.get(f"/reviews/{trigger_id}")

    assert resp.status_code == 200
    assert resp.json()["status"] == "reviewing"
    mock_status.assert_called_once_with("gw-fake0000002")


def _create_trigger(client) -> str:
    """Helper: get a valid trigger_id via a mocked webhook push, for tests
    that only care about the report endpoint downstream of it."""
    payload = {
        "ref": "refs/heads/main",
        "repository": {"clone_url": "https://github.com/octocat/Hello-World.git"},
        "commits": [],
    }
    body = json.dumps(payload).encode()
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-reportfake", "status": "requested"},
    ):
        create_resp = client.post(
            "/webhook",
            content=body,
            headers={"X-Hub-Signature-256": sign(body), "X-GitHub-Event": "push"},
        )
    return create_resp.json()["trigger_id"]


def test_get_review_report_unknown_trigger_returns_404(client):
    resp = client.get("/reviews/does-not-exist/report")
    assert resp.status_code == 404


def test_get_review_report_defaults_to_full_view(client):
    trigger_id = _create_trigger(client)

    with patch(
        "review_gateway.app.review_client.get_review_report",
        return_value={"reviews": [{"file": "a.py", "issues": [{"severity": "high"}]}]},
    ) as mock_report:
        resp = client.get(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 200
    mock_report.assert_called_once_with("gw-reportfake", view="full")


def test_get_review_report_forwards_custom_view(client):
    trigger_id = _create_trigger(client)

    with patch(
        "review_gateway.app.review_client.get_review_report",
        return_value={"files": [{"file": "a.py", "issues": 1}]},
    ) as mock_report:
        resp = client.get(f"/reviews/{trigger_id}/report", params={"view": "summary"})

    assert resp.status_code == 200
    mock_report.assert_called_once_with("gw-reportfake", view="summary")


def test_get_review_report_markdown_view_returns_plain_text(client):
    """review-api's markdown view is text/markdown, not JSON - the gateway
    used to force resp.json() on it regardless of view, which raised
    (JSONDecodeError) and surfaced to the browser as a CORS-looking
    "Failed to fetch" instead of a real response."""
    trigger_id = _create_trigger(client)

    with patch(
        "review_gateway.app.review_client.get_review_report",
        return_value="# Report\n\nEverything looks fine.",
    ) as mock_report:
        resp = client.get(f"/reviews/{trigger_id}/report", params={"view": "markdown"})

    assert resp.status_code == 200
    assert resp.text == "# Report\n\nEverything looks fine."
    assert resp.headers["content-type"].startswith("text/markdown")
    mock_report.assert_called_once_with("gw-reportfake", view="markdown")


def test_get_review_report_not_ready_is_404(client):
    trigger_id = _create_trigger(client)

    with patch(
        "review_gateway.app.review_client.get_review_report",
        side_effect=ReviewNotFound("no report yet for review 'gw-reportfake'"),
    ):
        resp = client.get(f"/reviews/{trigger_id}/report")

    assert resp.status_code == 404


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /reviews (manual trigger)
# ---------------------------------------------------------------------------

def test_manual_review_calls_review_api_and_stores_trigger(client):
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-manual001", "status": "requested"},
    ) as mock_start:
        resp = client.post(
            "/reviews",
            json={
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "branch": "main",
                "mode": "brief",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "status": "accepted",
        "event": "manual",
        "trigger_id": data["trigger_id"],
        "review_id": "gw-manual001",
    }
    mock_start.assert_called_once_with(
        repo_url="https://github.com/octocat/Hello-World.git",
        branch="main",
        files=None,
        mode="brief",
        # Nobody signed in for this request, so no token is forwarded.
        access_token="",
        findings_file=None,
        provider=None,
        llm=None,
    )


def test_manual_review_forwards_findings_file(client):
    """The gateway never reads or runs the scan - it only passes the
    filename through so review-api can load it (see scanner/README.md)."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-findings001", "status": "requested"},
    ) as mock_start:
        resp = client.post(
            "/reviews",
            json={
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "mode": "brief",
                "findings_file": "EVOTE.findings.json",
            },
        )

    assert resp.status_code == 200
    assert mock_start.call_args.kwargs["findings_file"] == "EVOTE.findings.json"


def test_manual_review_forwards_the_chosen_provider(client):
    """Choosing where the AI runs is the whole point of the selector: it is
    what stops a review depending on one particular machine being awake."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-prov001", "status": "requested"},
    ) as mock_start:
        resp = client.post(
            "/reviews",
            json={
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "mode": "brief",
                "provider": "lmstudio",
            },
        )

    assert resp.status_code == 200
    assert mock_start.call_args.kwargs["provider"] == "lmstudio"


def test_a_provider_address_is_not_accepted_only_a_name(client):
    """review-api also takes a raw `endpoint`, and forwarding one from a
    browser would turn this into an SSRF primitive: the caller could aim
    the server at 169.254.169.254 or at any other address it can reach and
    they cannot. Only a NAME travels, and the set of names is a deployment
    decision. Extra fields are ignored rather than rejected, so what this
    asserts is that nothing resembling an address reaches review-api."""
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-ssrf001", "status": "requested"},
    ) as mock_start:
        resp = client.post(
            "/reviews",
            json={
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "mode": "brief",
                "endpoint": "http://169.254.169.254/latest/meta-data/",
                "base_url": "http://169.254.169.254/",
            },
        )

    assert resp.status_code == 200
    sent = mock_start.call_args.kwargs
    assert "endpoint" not in sent
    assert "base_url" not in sent
    assert "169.254.169.254" not in str(sent)


def test_providers_are_listed_for_the_dashboard(client):
    with patch(
        "review_gateway.app.review_client.list_providers",
        return_value={"default": "lmstudio", "providers": [
            {"name": "lmstudio", "location": "on_prem"}]},
    ):
        resp = client.get("/providers")

    assert resp.status_code == 200
    assert resp.json()["default"] == "lmstudio"


def test_providers_degrade_to_an_empty_list_when_review_api_is_down(client):
    """Not being able to offer a choice is a smaller problem than a
    dashboard that will not load - the review still runs on the default."""
    with patch(
        "review_gateway.app.review_client.list_providers",
        side_effect=review_client.ReviewApiError("connection refused"),
    ):
        resp = client.get("/providers")

    assert resp.status_code == 200
    assert resp.json() == {"default": None, "providers": [], "unavailable": True}


def test_engine_busy_is_409_not_a_500(client):
    """review-api serialises reviews: while one runs, a second request gets
    409 with a body that has no review_id. The gateway used to read
    result["review_id"] from it and raise KeyError, so a user who merely
    arrived while someone else's review was running saw "Internal Server
    Error" and concluded the system was broken.

    The body below is review-api's real busy shape (backend app.py).
    """
    busy_body = {
        "status": "busy",
        "active": {"review_id": "gw-someone-else", "status": "reviewing"},
        "hint": "One review runs at a time. Retry when the active review finishes.",
    }
    with patch(
        "review_gateway.app.review_client.start_review",
        side_effect=ReviewApiBusy(busy_body["hint"]),
    ):
        resp = client.post(
            "/reviews",
            json={"repo_url": "https://github.com/octocat/Hello-World.git", "mode": "brief"},
        )

    assert resp.status_code == 409
    assert "One review runs at a time" in resp.json()["detail"]


def test_busy_detection_keys_on_the_missing_field_not_the_word(monkeypatch):
    """Guards the actual mechanism: a 409 without review_id is busy, even
    if the wording upstream changes."""
    from review_gateway import review_client

    class _Resp:
        status_code = 409

        @staticmethod
        def json():
            return {"status": "busy", "hint": "some future wording"}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **kw):
            return _Resp()

    monkeypatch.setattr(review_client.httpx, "Client", _Client)
    with pytest.raises(review_client.ReviewApiBusy):
        review_client.start_review(
            repo_url="https://github.com/o/r.git", branch="main", files=None
        )


def test_manual_review_rejects_bad_host(client):
    resp = client.post("/reviews", json={"repo_url": "https://evil.com/x/y.git"})
    assert resp.status_code == 400


def test_manual_review_missing_repo_url_is_422(client):
    resp = client.post("/reviews", json={})
    assert resp.status_code == 422  # pydantic validation, not our code


def test_manual_review_oversized_repo_url_is_422(client):
    huge_url = "https://github.com/" + "a" * 600
    resp = client.post("/reviews", json={"repo_url": huge_url})
    assert resp.status_code == 422


def test_manual_review_status_is_pollable_via_get_reviews(client):
    with patch(
        "review_gateway.app.review_client.start_review",
        return_value={"review_id": "gw-manual002", "status": "requested"},
    ):
        create_resp = client.post(
            "/reviews", json={"repo_url": "https://github.com/octocat/Hello-World.git"}
        )
    trigger_id = create_resp.json()["trigger_id"]

    with patch(
        "review_gateway.app.review_client.get_review_status",
        return_value={"review_id": "gw-manual002", "status": "reviewing"},
    ):
        resp = client.get(f"/reviews/{trigger_id}")

    assert resp.status_code == 200
    assert resp.json()["status"] == "reviewing"


# ---------------- per-file progress proxy ----------------

def test_get_review_files_proxies_to_the_review_id(client):
    trigger_id = _create_trigger(client)
    progress = {"review_id": "gw-reportfake", "status": "reviewing",
                "counts": {"total": 2, "done": 1, "failed": 0,
                           "in_progress": 1, "pending": 0},
                "files": [{"path": "a.py", "state": "done", "issues": 0},
                          {"path": "b.py", "state": "in_progress"}]}

    with patch("review_gateway.app.review_client.get_review_files",
               return_value=progress) as mock_files:
        resp = client.get(f"/reviews/{trigger_id}/files")

    assert resp.status_code == 200
    assert resp.json()["counts"]["done"] == 1
    mock_files.assert_called_once_with("gw-reportfake")


def test_get_review_files_before_the_plan_exists_is_404(client):
    """Normal for the first moments of a review, while it is still cloning:
    a 404 the polling UI retries, not an error."""
    trigger_id = _create_trigger(client)

    with patch("review_gateway.app.review_client.get_review_files",
               side_effect=ReviewNotFound("no per-file progress yet")):
        resp = client.get(f"/reviews/{trigger_id}/files")

    assert resp.status_code == 404


def test_get_review_files_unknown_trigger_returns_404(client):
    assert client.get("/reviews/does-not-exist/files").status_code == 404
