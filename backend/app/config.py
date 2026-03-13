"""
Contexta Backend - Configuration Module

This module handles all configuration settings using Pydantic Settings.
Environment variables are loaded from .env file or system environment.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import json


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = Field(default="Contexta", env="APP_NAME")
    app_env: str = Field(default="development", env="APP_ENV")
    debug: bool = Field(default=False, env="DEBUG")
    secret_key: str = Field(default="change-me-in-production", env="SECRET_KEY")
    api_v1_prefix: str = Field(default="/api/v1", env="API_V1_PREFIX")
    
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://contexta:contexta_password@localhost:5432/contexta_db",
        env="DATABASE_URL"
    )
    database_sync_url: str = Field(
        default="postgresql://contexta:contexta_password@localhost:5432/contexta_db",
        env="DATABASE_SYNC_URL"
    )
    
    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # JWT Settings
    jwt_secret_key: str = Field(default="jwt-secret-change-me", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Google Gemini API
    gemini_api_key: str = Field(default="", env="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-2.5-flash", env="GEMINI_MODEL")
    
    # CVE/NVD API
    nvd_api_key: Optional[str] = Field(default=None, env="NVD_API_KEY")
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        env="NVD_API_URL"
    )
    cisa_kev_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        env="CISA_KEV_URL"
    )
    
    # Scheduler Settings
    cve_fetch_interval_hours: int = Field(default=6, env="CVE_FETCH_INTERVAL_HOURS")
    log_generation_interval_minutes: int = Field(default=5, env="LOG_GENERATION_INTERVAL_MINUTES")
    risk_calculation_interval_minutes: int = Field(default=5, env="RISK_CALCULATION_INTERVAL_MINUTES")
    
    # Fake Log Generator Settings
    fake_logs_per_batch: int = Field(default=50, env="FAKE_LOGS_PER_BATCH")
    fake_log_enabled: bool = Field(default=True, env="FAKE_LOG_ENABLED")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    # CORS
    cors_origins: str = Field(
        default='["http://localhost:3000","http://localhost:3001","http://localhost:8080","http://127.0.0.1:3000","http://127.0.0.1:3001"]',
        env="CORS_ORIGINS"
    )
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(default=100, env="RATE_LIMIT_PER_MINUTE")
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from JSON string to list."""
        try:
            return json.loads(self.cors_origins)
        except json.JSONDecodeError:
            return ["http://localhost:3000"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Returns:
        Settings: Application settings singleton.
    """
    return Settings()


settings = get_settings()
