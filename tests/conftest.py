from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from datetime import datetime, timezone
import hashlib
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Ensure environment variables are set before application settings are imported.
os.environ.setdefault("PYTEST_ASYNCIO_MODE", "auto")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./tests/test.db")
os.environ.setdefault("DATABASE_POOL_SIZE", "5")
os.environ.setdefault("DATABASE_MAX_OVERFLOW", "10")
os.environ.setdefault("DATABASE_POOL_PRE_PING", "false")
os.environ.setdefault("DOCUMENT_VAULT_BUCKET", "document-vault-test")
os.environ.setdefault("AWS_S3_KMS_KEY_ID", "test-kms-key")
os.environ.setdefault("DOCUMENT_EVENTS_QUEUE_URL", "https://example.com/document-events")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("LOG_FORMAT", "json")
os.environ.setdefault("PRESIGNED_URL_EXPIRATION_SECONDS", "600")
os.environ.setdefault("ACCESS_CONTROL_ALLOW_ALL", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-access-key")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret-key")
os.environ.setdefault("AWS_SESSION_TOKEN", "test-session-token")

from app.api.dependencies import _event_publisher, _storage_service, _document_service  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.db.session import AsyncSessionFactory, engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.base import Base  # noqa: E402
from app.models.document import DocumentStatus, DocumentAuditEvent  # noqa: E402
from app.schemas.document import DocumentUploadMetadata  # noqa: E402
from app.services.hashing_service import HashingService  # noqa: E402


class FakeDocumentService:
    def __init__(self, storage_service, storage_bucket: str, storage_map: dict[str, bytes]):
        self._storage_service = storage_service
        self._storage_map = storage_map
        self._bucket = storage_bucket
        self._hashing = HashingService()
        self._documents: dict[str, SimpleNamespace] = {}

    async def upload_document(self, session, *, file, metadata: DocumentUploadMetadata):
        file.file.seek(0)
        sha256_hash = self._hashing.compute_sha256(file.file)
        storage_key, _ = await self._storage_service.upload_document(
            file.file,
            filename=file.filename or "document",
            mime_type=file.content_type or "application/octet-stream",
        )
        now = datetime.now(timezone.utc)
        doc_id = uuid4()

        document = SimpleNamespace(
            id=doc_id,
            entity_type=metadata.entity_type,
            entity_id=metadata.entity_id,
            token_id=metadata.token_id,
            document_type=metadata.document_type,
            filename=file.filename or "document",
            mime_type=file.content_type or "application/octet-stream",
            size_bytes=len(self._storage_map[storage_key]),
            storage_bucket=self._bucket,
            storage_key=storage_key,
            storage_version_id=None,
            sha256_hash=sha256_hash,
            status=DocumentStatus.UPLOADED,
            uploaded_by=metadata.uploaded_by,
            verified_by=None,
            archived_by=None,
            archived_at=None,
            hash_verified_at=None,
            on_chain_reference=None,
            metadata_json=dict(metadata.metadata),
            created_at=now,
            updated_at=now,
            _audit_logs_cache=[],
        )

        document._audit_logs_cache.append(
            SimpleNamespace(
                id=uuid4(),
                event_type=DocumentAuditEvent.UPLOAD,
                actor_id=metadata.uploaded_by,
                actor_role="uploader",
                notes=None,
                context={"filename": document.filename, "mime_type": document.mime_type},
                created_at=now,
            )
        )

        self._documents[str(doc_id)] = document
        return document

    async def verify_document(self, session, *, document_id, verifier_id):
        document = self._documents[str(document_id)]
        stored_bytes = self._storage_map[document.storage_key]
        calculated_hash = hashlib.sha256(stored_bytes).hexdigest()
        now = datetime.now(timezone.utc)

        if calculated_hash == document.sha256_hash:
            document.status = DocumentStatus.VERIFIED
            document.verified_by = verifier_id
            document.hash_verified_at = now
            document.on_chain_reference = f"tx-{document.sha256_hash[:16]}"
            event = DocumentAuditEvent.VERIFIED
        else:
            document.status = DocumentStatus.MISMATCH
            event = DocumentAuditEvent.MISMATCH

        document.updated_at = now
        document._audit_logs_cache.append(
            SimpleNamespace(
                id=uuid4(),
                event_type=event,
                actor_id=verifier_id,
                actor_role="verifier",
                notes=None,
                context=None,
                created_at=now,
            )
        )
        return document

    async def archive_document(self, session, *, document_id, archived_by):
        document = self._documents[str(document_id)]
        now = datetime.now(timezone.utc)
        document.status = DocumentStatus.ARCHIVED
        document.archived_by = archived_by
        document.archived_at = now
        document.updated_at = now
        document._audit_logs_cache.append(
            SimpleNamespace(
                id=uuid4(),
                event_type=DocumentAuditEvent.ARCHIVED,
                actor_id=archived_by,
                actor_role="admin",
                notes=None,
                context=None,
                created_at=now,
            )
        )
        return document

    async def list_documents(self, session, *, entity_id, entity_type):
        return [
            doc
            for doc in self._documents.values()
            if doc.entity_id == entity_id and doc.entity_type == entity_type
        ]

    async def get_document(self, session, document_id):
        return self._documents[str(document_id)]

    async def generate_download_url(self, session, *, document_id, requestor_id):
        document = self._documents[str(document_id)]
        url = await self._storage_service.generate_presigned_url(
            document.storage_key, settings.presigned_url_expiration_seconds
        )
        return document, url


@pytest_asyncio.fixture(autouse=True)
async def reset_database() -> AsyncGenerator[None, None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture
def aws_environment(monkeypatch) -> dict[str, object]:
    storage: dict[str, bytes] = {}
    events: list[dict[str, object]] = []

    async def upload_document(file_obj, *, filename: str, mime_type: str):
        file_obj.seek(0)
        data = file_obj.read()
        key = f"documents/{uuid4()}/{filename}"
        storage[key] = data
        return key, None

    async def stream_document(storage_key: str):
        data = storage[storage_key]
        yield data

    async def generate_presigned_url(storage_key: str, expires_in_seconds: int) -> str:
        return f"https://example.com/{storage_key}?expires={expires_in_seconds}"

    async def publish(*, event_type: str, payload: dict[str, object]) -> None:
        events.append({"event_type": event_type, "payload": payload})

    monkeypatch.setattr(_storage_service, "upload_document", upload_document, raising=True)
    monkeypatch.setattr(_storage_service, "stream_document", stream_document, raising=True)
    monkeypatch.setattr(_storage_service, "generate_presigned_url", generate_presigned_url, raising=True)
    monkeypatch.setattr(_event_publisher, "publish", publish, raising=True)

    fake_service = FakeDocumentService(_storage_service, settings.document_bucket, storage)
    monkeypatch.setattr("app.api.dependencies._document_service", fake_service, raising=False)

    return {"storage": storage, "events": events}


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def app_instance():
    return create_app()


@pytest_asyncio.fixture
async def async_client(app_instance) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app_instance)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
