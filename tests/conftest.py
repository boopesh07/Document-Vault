from __future__ import annotations

import os
import asyncio
from collections.abc import AsyncGenerator, Generator

import boto3
import pytest
from moto import mock_aws
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

# Ensure environment variables are set before application settings are imported.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./tests/test.db")
os.environ.setdefault("DATABASE_POOL_SIZE", "5")
os.environ.setdefault("DATABASE_MAX_OVERFLOW", "10")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("DOCUMENT_VAULT_BUCKET", "document-vault-test")
os.environ.setdefault("AWS_S3_KMS_KEY_ID", "arn:aws:kms:us-east-1:000000000000:key/mock")
os.environ.setdefault("DOCUMENT_EVENTS_QUEUE_URL", "https://sqs.mock.amazonaws.com/000000000000/document-events")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("LOG_FORMAT", "json")
os.environ.setdefault("PRESIGNED_URL_EXPIRATION_SECONDS", "600")
os.environ.setdefault("ACCESS_CONTROL_ALLOW_ALL", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

from app.core.config import settings  # noqa: E402
from app.db.session import AsyncSessionFactory, engine  # noqa: E402
from app.models.base import Base  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
async def reset_database() -> AsyncGenerator[None, None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture
def aws_environment() -> Generator[dict[str, str], None, None]:
    with mock_aws():
        s3_client = boto3.client("s3", region_name=settings.aws_region)
        if settings.aws_region == "us-east-1":
            s3_client.create_bucket(Bucket=settings.document_bucket)
        else:
            s3_client.create_bucket(
                Bucket=settings.document_bucket,
                CreateBucketConfiguration={"LocationConstraint": settings.aws_region},
            )

        sqs_client = boto3.client("sqs", region_name=settings.aws_region)
        queue = sqs_client.create_queue(QueueName="document-events")
        original_queue_url = settings.document_events_queue_url
        settings.document_events_queue_url = queue["QueueUrl"]

        yield {"queue_url": queue["QueueUrl"], "s3_client": s3_client, "sqs_client": sqs_client}

        settings.document_events_queue_url = original_queue_url


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def app_instance():
    return create_app()


@pytest.fixture
async def async_client(app_instance) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=app_instance, base_url="http://test") as client:
        yield client
