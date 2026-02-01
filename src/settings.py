from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Unified Governance Layer")
    db_path: str = os.getenv("DB_PATH", "./data/app.db")
    evidence_hmac_secret: str = os.getenv("EVIDENCE_HMAC_SECRET", "dev-secret-change")


settings = Settings()
