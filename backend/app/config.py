from __future__ import annotations

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "ArgoLock"
    environment: str = "development"
    secret_key: str = "change-me-in-production"
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── MongoDB ───────────────────────────────────────────────────────────────
    mongodb_url: str = "mongodb://mongodb:27017"
    mongodb_db: str = "argolock"

    # ── Redis / Celery ────────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"

    # ── AI Provider ───────────────────────────────────────────────────────────
    ai_provider: str = "openai"          # openai | claude | ollama
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "llama3"

    # ── Tool Execution ────────────────────────────────────────────────────────
    tool_execution_mode: str = "docker"  # docker | subprocess
    tool_timeout_seconds: int = 300
    nmap_docker_image: str = "instrumentisto/nmap:latest"
    nuclei_docker_image: str = "projectdiscovery/nuclei:latest"
    nikto_docker_image: str = "frapsoft/nikto:latest"
    sqlmap_docker_image: str = "paoloo/sqlmap:latest"
    subfinder_docker_image: str = "projectdiscovery/subfinder:latest"
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = "argolock-zap-key"

    # ── Reports ───────────────────────────────────────────────────────────────
    reports_dir: str = "/tmp/argolock_reports"

    # ── Safety ────────────────────────────────────────────────────────────────
    safe_mode: bool = True
    max_concurrent_scans: int = 3
    rate_limit_per_minute: int = 10


settings = Settings()
