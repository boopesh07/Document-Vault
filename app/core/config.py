from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    project_name: str = "Document Vault Service"
    environment: Literal["local", "dev", "staging", "prod"] = Field("local", alias="ENVIRONMENT")
    api_v1_prefix: str = "/api/v1"

    # Security & auth
    jwt_public_key: str | None = Field(default=None, alias="JWT_PUBLIC_KEY")
    access_control_allow_all: bool = Field(True, alias="ACCESS_CONTROL_ALLOW_ALL")

    # Database
    database_url: str = Field(..., alias="DATABASE_URL")
    database_pool_size: int = Field(5, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(10, alias="DATABASE_MAX_OVERFLOW")

    # AWS / S3 storage
    aws_region: str = Field(..., alias="AWS_REGION")
    aws_profile: str | None = Field(default=None, alias="AWS_PROFILE")
    document_bucket: str = Field(..., alias="DOCUMENT_VAULT_BUCKET")
    s3_kms_key_id: str = Field(..., alias="AWS_S3_KMS_KEY_ID")
    s3_endpoint_url: AnyHttpUrl | None = Field(default=None, alias="AWS_S3_ENDPOINT_URL")
    presigned_url_expiration_seconds: int = Field(900, alias="PRESIGNED_URL_EXPIRATION_SECONDS")

    # Queueing / events
    document_events_queue_url: str = Field(..., alias="DOCUMENT_EVENTS_QUEUE_URL")

    # Blockchain integration (mocked for now)
    blockchain_endpoint_url: AnyHttpUrl | None = Field(default=None, alias="BLOCKCHAIN_ENDPOINT_URL")

    # Observability
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    log_format: Literal["json", "text"] = Field("json", alias="LOG_FORMAT")

    class Config:
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
