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
    policy_approval_secret: str = os.getenv("POLICY_APPROVAL_SECRET", "dev-policy-approval")
    evidence_vault_path: str = os.getenv("EVIDENCE_VAULT_PATH", "./output/evidence_vault.log")
    risk_score_threshold: int = int(os.getenv("RISK_SCORE_THRESHOLD", "7"))
    attestations_public_ledger: str | None = os.getenv("ATTESTATIONS_PUBLIC_LEDGER")
    secret_provider: str | None = os.getenv("SECRET_PROVIDER")
    license_key: str | None = os.getenv("LICENSE_KEY")
    license_strict: bool = os.getenv("LICENSE_STRICT", "false").lower() == "true"
    decision_cache_size: int = int(os.getenv("DECISION_CACHE_SIZE", "512"))
    decision_cache_ttl: int = int(os.getenv("DECISION_CACHE_TTL", "60"))
    oidc_issuer: str | None = os.getenv("OIDC_ISSUER")
    oidc_audience: str | None = os.getenv("OIDC_AUDIENCE")
    oidc_strict: bool = os.getenv("OIDC_STRICT", "false").lower() == "true"
    siem_hec_url: str | None = os.getenv("SIEM_HEC_URL")
    siem_hec_token: str | None = os.getenv("SIEM_HEC_TOKEN")
    retention_days: int = int(os.getenv("RETENTION_DAYS", "90"))
    decision_log_retention_days: int = int(os.getenv("DECISION_LOG_RETENTION_DAYS", "180"))
    webhook_delivery_retention_days: int = int(os.getenv("WEBHOOK_DELIVERY_RETENTION_DAYS", "30"))
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    enable_webhook_delivery: bool = os.getenv("ENABLE_WEBHOOK_DELIVERY", "false").lower() == "true"
    rate_limit_per_min: int = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
    enable_sso_enforcement: bool = os.getenv("ENABLE_SSO_ENFORCEMENT", "false").lower() == "true"


settings = Settings()
