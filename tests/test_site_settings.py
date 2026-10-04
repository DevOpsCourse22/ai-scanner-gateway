"""Site-wide AI service (admins only, key encrypted) and deleting a review."""

import dataclasses
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from review_gateway import db as gateway_db
from review_gateway import site_settings
from review_gateway.app import app

from test_auth import _log_in

KEY = "sk-live-0123456789abcdefWXYZ"
REPO = "https://github.com/octocat/Hello-World"


@pytest.fixture(autouse=True)
def site(monkeypatch, tmp_path):
    """An admins file naming one admin, an encryption key, no AI row."""
    admins = tmp_path / "admins"
    admins.write_text("# site admins\nsite-admin\n", encoding="utf-8")
    new = dataclasses.replace(site_settings.settings, admins_file=str(admins),
                              admins="", settings_encryption_key="k" * 64)
    monkeypatch.setattr(site_settings, "settings", new)
    session = gateway_db.get_session()
    site_settings.clear_ai(session)
    session.close()
    return admins


def _admin():
    client = TestClient(app)
    _log_in(client, login="site-admin", user_id=77001)
    return client


def _user():
    client = TestClient(app)
    _log_in(client, login="plain-user", user_id=77002)
    return client


def test_me_says_who_is_an_admin():
    assert _admin().get("/auth/me").json()["is_admin"] is True
    assert _user().get("/auth/me").json()["is_admin"] is False


def test_the_admins_file_is_reread_when_it_changes(site):
    user = _user()
    assert user.get("/auth/me").json()["is_admin"] is False
    site.write_text("site-admin, Plain-User\n", encoding="utf-8")
    import os
    os.utime(site, (1, 1))              # a new mtime, as a ConfigMap sync gives
    assert user.get("/auth/me").json()["is_admin"] is True


def test_numeric_ids_work_too(site):
    site.write_text("id:77002\n", encoding="utf-8")
    import os
    os.utime(site, (2, 2))
    assert _user().get("/auth/me").json()["is_admin"] is True


def test_only_admins_can_change_the_ai_service():
    body = {"preset": "openai", "model": "gpt-x", "api_key": KEY}
    assert _user().put("/providers/ai", json=body).status_code == 403
    assert TestClient(app).put("/providers/ai", json=body).status_code == 401
    resp = _admin().put("/providers/ai", json=body)
    assert resp.status_code == 200
    saved = resp.json()
    assert saved["preset"] == "openai" and saved["key_saved"] is True
    assert saved["key_hint"] == "…WXYZ"
    assert KEY not in json.dumps(saved)


def test_everyone_signed_in_can_read_it_but_never_the_key():
    _admin().put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    seen = _user().get("/providers/ai").json()
    assert seen["configured"] and seen["can_edit"] is False
    assert KEY not in json.dumps(seen)


def test_the_key_is_stored_encrypted():
    _admin().put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    session = gateway_db.get_session()
    row = session.get(gateway_db.SiteSetting, "ai")
    assert KEY not in (row.secret_enc or "") and KEY not in row.value
    assert site_settings.ai_for_review(session)["api_key"] == KEY
    session.close()


def test_saving_without_a_key_keeps_it_but_a_new_service_drops_it():
    admin = _admin()
    admin.put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    kept = admin.put("/providers/ai", json={"preset": "openai", "model": "m2"})
    assert kept.json()["key_saved"] is True
    moved = admin.put("/providers/ai", json={"preset": "groq"})
    assert moved.json()["key_saved"] is False


def test_no_encryption_key_means_no_key_can_be_saved(monkeypatch):
    monkeypatch.setattr(site_settings, "settings", dataclasses.replace(
        site_settings.settings, settings_encryption_key=""))
    admin = _admin()
    assert admin.put("/providers/ai", json={
        "preset": "openai", "api_key": KEY}).status_code == 503
    # A key-less local server still works.
    assert admin.put("/providers/ai", json={
        "preset": "local", "endpoint": "100.64.0.5"}).status_code == 200


def test_a_changed_encryption_key_stops_reviews_with_a_reason(monkeypatch):
    _admin().put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    monkeypatch.setattr(site_settings, "settings", dataclasses.replace(
        site_settings.settings, settings_encryption_key="other" * 10))
    with patch("review_gateway.app.review_client.start_review") as start:
        resp = TestClient(app).post("/reviews", json={"repo_url": REPO})
    assert resp.status_code == 503
    assert "enter the key again" in resp.json()["detail"]
    start.assert_not_called()


def test_reviews_carry_the_site_choice():
    _admin().put("/providers/ai", json={"preset": "openai", "model": "gpt-x",
                                        "api_key": KEY})
    with patch("review_gateway.app.review_client.start_review",
               return_value={"review_id": "gw-ai0001", "status": "requested"}) as start:
        assert TestClient(app).post("/reviews", json={"repo_url": REPO}).status_code == 200
    assert start.call_args.kwargs["llm"] == {
        "preset": "openai", "endpoint": "", "model": "gpt-x", "api_key": KEY}


def test_the_client_sends_the_key_in_a_header_not_the_body():
    from review_gateway import review_client
    body, headers = {}, {}
    review_client._add_llm(body, headers, {"preset": "openai", "model": "m",
                                           "endpoint": "", "api_key": KEY})
    assert body == {"llm": {"preset": "openai", "model": "m"}}
    assert headers["X-LLM-Key"] == KEY


def test_testing_uses_the_saved_key_for_the_same_service():
    admin = _admin()
    admin.put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    with patch("review_gateway.app.review_client.llm_test",
               return_value={"reachable": False, "error": f"401 {KEY}"}) as test:
        resp = admin.post("/providers/ai/test", json={"preset": "openai"})
    assert test.call_args.args[0]["api_key"] == KEY
    assert KEY not in resp.text
    assert _user().post("/providers/ai/test",
                        json={"preset": "openai"}).status_code == 403


def test_reset_goes_back_to_the_server_default():
    admin = _admin()
    admin.put("/providers/ai", json={"preset": "openai", "api_key": KEY})
    assert admin.delete("/providers/ai").json()["configured"] is False
    session = gateway_db.get_session()
    assert site_settings.ai_for_review(session) is None
    session.close()


# ---------------- deleting a review ----------------

def _start(client, review_id):
    with patch("review_gateway.app.review_client.start_review",
               return_value={"review_id": review_id, "status": "requested"}):
        return client.post("/reviews", json={"repo_url": REPO}).json()["trigger_id"]


def test_owner_deletes_a_running_review_it_is_paused_first():
    owner = _user()
    trigger_id = _start(owner, "gw-del0001")
    with patch("review_gateway.app.review_client.pause_review") as pause, \
         patch("review_gateway.app.review_client.delete_review",
               return_value={"removed": ["gw-del0001.json"]}) as delete:
        resp = owner.delete(f"/reviews/{trigger_id}")
    assert resp.status_code == 200
    pause.assert_called_once_with("gw-del0001")
    delete.assert_called_once_with("gw-del0001")
    assert owner.get(f"/reviews/{trigger_id}").status_code == 404
    assert all(r["trigger_id"] != trigger_id for r in owner.get("/reviews").json())


def test_someone_else_cannot_delete_it():
    trigger_id = _start(_user(), "gw-del0002")
    other = TestClient(app)
    _log_in(other, login="stranger", user_id=77003)
    with patch("review_gateway.app.review_client.delete_review") as delete:
        assert other.delete(f"/reviews/{trigger_id}").status_code == 404
    delete.assert_not_called()


def test_still_stopping_is_a_409_and_the_row_stays():
    from review_gateway import review_client
    owner = _user()
    trigger_id = _start(owner, "gw-del0003")
    with patch("review_gateway.app.review_client.pause_review"), \
         patch("review_gateway.app.review_client.delete_review",
               side_effect=review_client.ReviewStillRunning("running")):
        assert owner.delete(f"/reviews/{trigger_id}").status_code == 409
    session = gateway_db.get_session()
    assert session.get(gateway_db.Trigger, trigger_id) is not None
    session.close()
