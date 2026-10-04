"""Points the gateway at an isolated, file-based SQLite DB before anything
imports review_gateway.db - Settings reads env vars once, at import time.
An in-memory DB would work too but resets between connections without extra
pooling config; a throwaway temp file avoids that footgun.
"""

import os
import tempfile

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["GATEWAY_DATABASE_URL"] = f"sqlite:///{_tmp_db.name}"
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret")
