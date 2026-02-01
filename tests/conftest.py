import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("DB_PATH", os.path.join(ROOT, "data", "test.db"))
os.environ.setdefault("EVIDENCE_HMAC_SECRET", "test-secret")

from src.db import init_db  # noqa: E402

init_db()
