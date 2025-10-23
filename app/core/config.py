from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    project_name: str = "Document Vault Service"
    environment: Literal["local", "dev", "staging", "prod", "test"] = Field("local", alias="ENVIRONMENT")
    api_v1_prefix: str = "/api/v1"

    # Security & auth
    jwt_public_key: str | None = Field(default=None, alias="JWT_PUBLIC_KEY")
    epr_service_url: AnyHttpUrl | None = Field(default=None, alias="EPR_SERVICE_URL")

    # Database
    database_url: str = Field(..., alias="DATABASE_URL")
    database_pool_size: int = Field(5, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(10, alias="DATABASE_MAX_OVERFLOW")
    database_pool_pre_ping: bool = Field(True, alias="DATABASE_POOL_PRE_PING")

    # AWS / S3 storage
    aws_region: str = Field(..., alias="AWS_REGION")
    aws_profile: str | None = Field(default=None, alias="AWS_PROFILE")
    aws_access_key_id: str | None = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: str | None = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")
    aws_session_token: str | None = Field(default=None, alias="AWS_SESSION_TOKEN")
    document_bucket: str = Field(..., alias="DOCUMENT_VAULT_BUCKET")
    s3_kms_key_id: str = Field(..., alias="AWS_S3_KMS_KEY_ID")
    s3_endpoint_url: AnyHttpUrl | None = Field(default=None, alias="AWS_S3_ENDPOINT_URL")
    presigned_url_expiration_seconds: int = Field(900, alias="PRESIGNED_URL_EXPIRATION_SECONDS")

    # Queueing / events
    document_events_queue_url: str = Field(..., alias="DOCUMENT_EVENTS_QUEUE_URL")
    audit_sns_topic_arn: str = Field(..., alias="AUDIT_SNS_TOPIC_ARN")
    
    # Document Vault Consumer (entity deletion events)
    enable_document_consumer: bool = Field(default=True, alias="ENABLE_DOCUMENT_CONSUMER")
    document_vault_sqs_url: str | None = Field(default=None, alias="DOCUMENT_VAULT_SQS_URL")
    document_consumer_max_messages: int = Field(default=5, alias="DOCUMENT_CONSUMER_MAX_MESSAGES")
    document_consumer_wait_time: int = Field(default=20, alias="DOCUMENT_CONSUMER_WAIT_TIME")
    document_consumer_visibility_timeout: int | None = Field(default=None, alias="DOCUMENT_CONSUMER_VISIBILITY_TIMEOUT")

    # EPR Service
    epr_service_url: AnyHttpUrl | None = Field(default=None, alias="EPR_SERVICE_URL")
    epr_service_timeout: int = Field(default=5, alias="EPR_SERVICE_TIMEOUT")
    epr_mock_mode: bool = Field(default=True, alias="EPR_MOCK_MODE")

    @field_validator("epr_service_url", mode="before")
    @classmethod
    def _validate_epr_url(cls, v: str | None) -> str | None:
        if v and v.startswith("tcp://"):
            return v.replace("tcp://", "http://", 1)
        return v

    # Blockchain integration (mocked for now)
    blockchain_endpoint_url: AnyHttpUrl | None = Field(default=None, alias="BLOCKCHAIN_ENDPOINT_URL")

    # Observability
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    log_format: Literal["json", "text"] = Field("json", alias="LOG_FORMAT")

    presigned_url_expiration_seconds: int = 3600

    @field_validator(
        "aws_profile",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "s3_endpoint_url",
        "blockchain_endpoint_url",
        "epr_service_url",
        mode="before",
    )
    @classmethod
    def blank_to_none(cls, value: str | None):
        if isinstance(value, str) and value.strip() == "":
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
