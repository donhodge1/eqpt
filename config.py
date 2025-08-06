# config.py
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
import secrets


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Community Tool Rental"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # API
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days

    # Database
    DATABASE_URL: str = "sqlite:///./toolrental.db"

    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @property
    def BACKEND_CORS_ORIGINS_LIST(self) -> List[str]:
        # Convert to list of strings for CORS middleware
        return [str(origin) for origin in self.BACKEND_CORS_ORIGINS]

    # First superuser
    FIRST_SUPERUSER_USERNAME: str = "admin"
    FIRST_SUPERUSER_PASSWORD: str = "admin"
    FIRST_SUPERUSER_EMAIL: str = "admin@toolrental.com"

    # Pagination
    DEFAULT_LIMIT: int = 20
    MAX_LIMIT: int = 100

    # Feature flags
    ENABLE_GROUPS: bool = False
    ENABLE_RATINGS: bool = False
    ENABLE_PAYMENTS: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings instance
settings = Settings()