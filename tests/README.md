# Gateway test suite

This test directory covers the AI Scan Repos gateway layer: GitHub webhook
validation, OAuth login flow, review trigger handling, database resilience and
admin settings. The tests validate the gateway contract without calling the
real backend review API.

## What is covered

| File | Purpose |
|---|---|
| `conftest.py` | Bootstraps a temporary SQLite database and a known test webhook secret so each test starts from a clean gateway state |
| `test_app.py` | Webhook validation, event routing, trigger creation, proxying status/report calls, and review start errors |
| `test_auth.py` | GitHub OAuth login, callback validation, session creation, logout, and deep-review permission checks |
| `test_db_resilience.py` | Pool safety, dead-connection recovery and protection against leaking bound values into logs |
| `test_pause_resume.py` | Pause/resume workflow, owner checks, resumed review validation, and gateway-side status continuity |
| `test_site_settings.py` | Admin-only AI settings, encrypted storage, per-user preferences, and review deletion rules |

## How to run

```bash
pip install -e ".[dev]"
pytest -q
```

Or to focus on one area:

```bash
pytest tests/test_auth.py -q
pytest tests/test_pause_resume.py -q
pytest tests/test_site_settings.py -q
```

## Test philosophy

The gateway tests are intentionally isolated from the real review engine. They
mock `review_client` calls and verify the API contract at the gateway boundary:
request validation, authorization, status forwarding, and result persistence.

This keeps the tests stable while still exercising the real FastAPI app and the
database behavior that matters to the platform.
