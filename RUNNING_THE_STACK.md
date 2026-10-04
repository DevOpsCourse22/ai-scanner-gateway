# Running the full stack

Two ways to run everything end to end: with a **mock AI** (no GPU, no
LM Studio, works on any machine) or with **Elad's real AI** over Tailscale.
Both use the same services — only the `LMSTUDIO_BASE_URL` value changes.

```
React Dashboard :5173 ──▶ gateway :8080 ──▶ backend :8000 ──▶ LM Studio (mock or real)
GitHub / curl    ─────────────▲
                          (webhook or manual POST /reviews)
```

The React app (`Code-Review-MCP/frontend-react/`) talks to the **gateway**,
not backend directly - that's how it gets GitHub login and the deep-mode
gate for free. Elad's test console (`Code-Review-MCP/frontend/`) still
works too, for quick backend-only testing without the gateway in the loop -
see the bottom of this doc. Since 2026-09-17 it is its own service
(`review-console`); backend no longer serves it.

## Part 1 — local stack with a mock AI

No AI model, no GPU needed - `mock_llm_server.py` is stdlib-only and always
returns valid review JSON. Good for testing the pipeline, demos, and CI.

**One-time install** (from the repository root):

```powershell
pip install -e ./Code-Review-MCP/mcp-server -e "./Code-Review-MCP/backend[dev]" -e "./Code-Review-MCP/gateway[dev]"
```

**Also needed for the React app: Node.js LTS.** If `node --version` fails:

```powershell
winget install OpenJS.NodeJS.LTS
```

Then, once (installs the React app's dependencies):

```powershell
cd Code-Review-MCP/frontend-react
npm install
cd ../..
```

**Terminal 1 — mock LLM:**

```powershell
python Code-Review-MCP/mcp-server/tests/mock_llm_server.py --port 8765
```

**Terminal 2 — backend, pointed at the mock:**

```powershell
$env:LMSTUDIO_BASE_URL = "http://localhost:8765/v1"
python -m review_api.app
```

Backend is API-only: **http://127.0.0.1:8000/** answers with a small JSON
descriptor, not a page. For the test console, open
`Code-Review-MCP/frontend/index.html` straight from disk — its API base
already defaults to `http://localhost:8000` — and it should say
*"local API · lmstudio reachable (1 models)"*. (With Docker instead,
`docker compose up` runs it on http://127.0.0.1:8090.)

**Terminal 3 — gateway, pointed at the backend:**

```powershell
cd Code-Review-MCP/gateway
cp .env.example .env    # first time only - then fill in the real values below
python -m review_gateway.app
```

In `.env`, at minimum set `GITHUB_WEBHOOK_SECRET` (anything, for local
testing) and, for GitHub login to work, `GITHUB_OAUTH_CLIENT_ID` +
`GITHUB_OAUTH_CLIENT_SECRET` from a GitHub OAuth App (see
`gateway/README.md` for the exact steps) - **ask Sahar for the client
secret rather than generating a new OAuth App**, it's already registered
for this project. `REVIEW_API_BASE_URL` defaults to `http://localhost:8000`,
which is correct for this local setup.

**Terminal 4 — the React Dashboard:**

```powershell
cd Code-Review-MCP/frontend-react
npm run dev
```

Open **http://localhost:5173** - login (optional, only `deep` mode needs
it), submit a repo, watch the live status/progress bar, see the report.

**Try the API directly** (manual trigger, no GitHub/browser needed):

```powershell
$body = '{"repo_url": "https://github.com/octocat/Spoon-Knife.git", "branch": "main", "mode": "brief", "files": ["index.html"]}'
Invoke-RestMethod -Uri http://localhost:8080/reviews -Method Post -Body $body -ContentType "application/json"
# -> {"trigger_id": "...", "review_id": "..."}
Invoke-RestMethod -Uri "http://localhost:8080/reviews/<trigger_id>"
```

Pick a repo with real source files - `octocat/Hello-World` is *just* a
README and fails with "No reviewable code files found" (expected, not a
bug). A private repo fails with a clear "no GITHUB_TOKEN configured"
message rather than a confusing generic error.

## Part 2 — real AI on Elad's machine (over Tailscale)

**Not testable yet from this machine** — `tailscale ping 100.93.244.39`
currently returns `no matching peer`, meaning this machine isn't on Elad's
tailnet. Prerequisite before any of this works: Elad adds you to his
tailnet, or shares that specific node with your Tailscale account (see the
two options we discussed earlier). Confirm with:

```powershell
tailscale ping 100.93.244.39
```

Once that succeeds, everything is identical to Part 1 **except Terminal 2**:

```powershell
$env:LMSTUDIO_BASE_URL = "http://100.93.244.39:1234/v1"
python -m review_api.app
```

Terminal 1 (mock) isn't needed at all in this mode - backend talks
straight to Elad's real LM Studio. Terminals 3 (gateway) and 4 (React) are
unchanged.

**Open question for Elad, not yet resolved:** he mentioned giving REST
access to his LM Studio directly (`100.93.244.39:1234`, the setup above).
It's worth confirming whether he *also* wants to run his own `backend`
instance and expose that instead (in which case Terminal 2 disappears
entirely and the gateway's `REVIEW_API_BASE_URL` points straight at his
backend's Tailscale address). Both are valid; they change who runs
`backend` — you or him — not how the gateway works.

## Either way: two frontends, two different jobs

- **`Code-Review-MCP/frontend-react/`** (Terminal 4, port 5173) - the real
  Dashboard. Talks to the **gateway**: GitHub login, the deep-mode gate,
  the trigger/review_id mapping. This is what end users would actually use.
- **`Code-Review-MCP/frontend/index.html`** (Elad's test console - open the
  file, or the `review-console` container on `:8090`) - talks to
  **backend directly**, bypassing the
  gateway entirely (no login, no deep-mode gate). Still useful for
  low-level testing of backend/review-api itself (restart, cancel, dry-run
  prompts, raw JSON) - not for testing anything gateway-related.

## What's built in the React app so far (2026-08-15)

Login (optional - only `deep` mode requires it), submit a review
(quick/brief/deep), live status polling with a progress bar, automatic
report display on completion, a "wrong account?" link for switching GitHub
accounts, a summary/full/markdown report view selector, Copy and Download
buttons on the report, character limits on the repo URL/branch fields, an
in-app "how to set up a webhook" guide, and **My Reviews** - a logged-in
user's own review history (repo, branch, mode, date - never the report
content itself, which is always re-fetched live from review-api when you
click "View"; see `gateway/src/review_gateway/app.py`'s `GET /reviews`).
Source: `frontend-react/src/{App,ReviewForm,ReviewStatus,MyReviews,api}.tsx|ts`.

**Two real bugs found and fixed, worth knowing about:**
- Giving a child component a `key` tied to its identifying prop (here,
  `key={trigger_id}` on `<ReviewStatus>`) forces React to reset its
  internal state when that identity changes. Without it, starting a second
  review reused the first one's leftover `status` state for one render,
  which briefly (and incorrectly) looked like the new review was already
  "completed." See commit `a66fb45` for the full trace.
- `review_client.get_review_report()` used to call `resp.json()` on every
  response regardless of `view=`, but `view=markdown` comes back as plain
  `text/markdown`, not JSON - that raised inside the gateway and surfaced
  to the browser as a CORS-looking "Failed to fetch" instead of a real
  error. Fixed in commit `6049952`; `view=markdown` now returns a real
  `PlainTextResponse`.

**Known rough edge, not fixed yet:** pasting a URL straight from GitHub's
address bar while browsing a branch (`.../tree/main`) is rejected by
`validate_repo_url()` - it only accepts a bare `https://github.com/<owner>/
<repo>`. This is intentional (defense in depth on the URL format), but
it's a very natural mistake since that's exactly what GitHub shows you.
Worth doing next: parse `/tree/<branch>` out and auto-fill the branch
field instead of rejecting it outright.

**Not built yet:** more error-state polish, and whatever Elad/Aviel pick
up next (Aviel is planning to reorganize the repo's folder structure and
implement the deterministic-check tests, so paths referenced in this doc
may move).
