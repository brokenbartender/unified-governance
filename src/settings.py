from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Unified Governance Layer")
    db_path: str = os.getenv("DB_PATH", "./data/app.db")
    db_url: str | None = os.getenv("DB_URL")
    evidence_hmac_secret: str = os.getenv("EVIDENCE_HMAC_SECRET", "dev-secret-change")
    retention_days: int = int(os.getenv("RETENTION_DAYS", "90"))
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    enable_webhook_delivery: bool = os.getenv("ENABLE_WEBHOOK_DELIVERY", "false").lower() == "true"
    rate_limit_per_min: int = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
    enable_sso_enforcement: bool = os.getenv("ENABLE_SSO_ENFORCEMENT", "false").lower() == "true"


settings = Settings()
