from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Sequence
from uuid import UUID

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logger import get_logger
from app.events.publisher import DocumentEventPublisher
from app.models.document import (
    Document,
    DocumentAuditEvent,
    DocumentStatus,
    DocumentEntityType,
)
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_service import AuditService
from app.services.blockchain_service import BlockchainService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService

logger = get_logger(component="DocumentService")


class DocumentNotFoundError(Exception):
    """Raised when attempting to operate on a missing document."""


class DocumentService:
    def __init__(
        self,
        storage_service: StorageService,
        hashing_service: HashingService,
        audit_service: AuditService,
        access_control_service: EprServiceMock,
        blockchain_service: BlockchainService,
        event_publisher: DocumentEventPublisher,
    ) -> None:
        self.storage_service = storage_service
        self.hashing_service = hashing_service
        self.audit_service = audit_service
        self.access_control_service = access_control_service
        self.blockchain_service = blockchain_service
        self.event_publisher = event_publisher

    async def upload_document(
        self, session: AsyncSession, *, file: UploadFile, metadata: DocumentUploadMetadata
    ) -> Document:
        is_allowed = await self.access_control_service.is_authorized(
            user_id=metadata.uploaded_by, action="document:upload", resource_id=metadata.entity_id
        )
        if not is_allowed:
            raise PermissionError("Upload not authorized")

        underlying_file = file.file
        underlying_file.seek(0)
        sha256_hash = self.hashing_service.compute_sha256(underlying_file)

        underlying_file.seek(0, os.SEEK_END)
        size_bytes = underlying_file.tell()
        underlying_file.seek(0)

        storage_key, version_id = await self.storage_service.upload_document(
            underlying_file,
            filename=file.filename or "document",
            mime_type=file.content_type or "application/octet-stream",
        )

        document = Document(
            entity_type=metadata.entity_type,
            entity_id=metadata.entity_id,
            token_id=metadata.token_id,
            document_type=metadata.document_type,
            filename=file.filename or "document",
            mime_type=file.content_type or "application/octet-stream",
            size_bytes=size_bytes,
            storage_bucket=settings.document_bucket,
            storage_key=storage_key,
            storage_version_id=version_id,
            sha256_hash=sha256_hash,
            status=DocumentStatus.UPLOADED,
            uploaded_by=metadata.uploaded_by,
            metadata_json=metadata.metadata.model_dump() if metadata.metadata else None,
        )
        session.add(document)
        await session.flush()

        audit_log = await self.audit_service.log_event(
            session,
            document_id=document.id,
            event_type=DocumentAuditEvent.UPLOAD,
            actor_id=metadata.uploaded_by,
            actor_role="uploader",
            context={"filename": document.filename, "mime_type": document.mime_type},
        )
        document.__dict__.setdefault("_audit_logs_cache", []).append(audit_log)

        await self.event_publisher.publish(
            event_type=DocumentAuditEvent.UPLOAD.value,
            payload={
                "document_id": str(document.id),
                "entity_type": document.entity_type.value,
                "entity_id": str(document.entity_id),
                "sha256_hash": document.sha256_hash,
                "status": document.status.value,
            },
        )

        logger.info("Document uploaded", document_id=str(document.id), storage_key=storage_key)
        return document

    async def verify_document(
        self, session: AsyncSession, *, document_id: UUID, verifier_id: UUID
    ) -> Document:
        document = await self._get_document(session, document_id)

        is_allowed = await self.access_control_service.is_authorized(
            user_id=verifier_id, action="document:verify", resource_id=document.entity_id
        )
        if not is_allowed:
            raise PermissionError("Verify not authorized")

        sha256_hash = self.hashing_service.create_digest()
        async for chunk in self.storage_service.stream_document(document.storage_key):
            sha256_hash.update(chunk)
        calculated_hash = sha256_hash.hexdigest()

        if calculated_hash == document.sha256_hash:
            document.status = DocumentStatus.VERIFIED
            document.hash_verified_at = datetime.now(tz=timezone.utc)
            document.verified_by = verifier_id
            document.on_chain_reference = await self.blockchain_service.register_document(
                token_id=document.token_id,
                document_hash=document.sha256_hash,
                metadata_uri=None,
            )
            audit_log = await self.audit_service.log_event(
                session,
                document_id=document.id,
                event_type=DocumentAuditEvent.VERIFIED,
                actor_id=verifier_id,
                actor_role="verifier",
            )
            document.__dict__.setdefault("_audit_logs_cache", []).append(audit_log)
            await self.event_publisher.publish(
                event_type=DocumentAuditEvent.VERIFIED.value,
                payload={
                    "document_id": str(document.id),
                    "entity_type": document.entity_type.value,
                    "entity_id": str(document.entity_id),
                    "sha256_hash": document.sha256_hash,
                },
            )
        else:
            document.status = DocumentStatus.MISMATCH
            audit_log = await self.audit_service.log_event(
                session,
                document_id=document.id,
                event_type=DocumentAuditEvent.MISMATCH,
                actor_id=verifier_id,
                actor_role="verifier",
                context={"expected_hash": document.sha256_hash, "calculated_hash": calculated_hash},
            )
            document.__dict__.setdefault("_audit_logs_cache", []).append(audit_log)
            await self.event_publisher.publish(
                event_type=DocumentAuditEvent.MISMATCH.value,
                payload={
                    "document_id": str(document.id),
                    "expected_hash": document.sha256_hash,
                    "calculated_hash": calculated_hash,
                    "entity_id": str(document.entity_id),
                },
            )

        
        logger.info("Document verification processed", document_id=str(document.id), status=document.status.value)
        return document

    async def archive_document(
        self, session: AsyncSession, *, document_id: UUID, archived_by: UUID
    ) -> Document:
        document = await self._get_document(session, document_id)

        is_allowed = await self.access_control_service.is_authorized(
            user_id=archived_by, action="document:archive", resource_id=document.entity_id
        )
        if not is_allowed:
            raise PermissionError("Archive not authorized")

        document.status = DocumentStatus.ARCHIVED
        document.archived_at = datetime.now(tz=timezone.utc)
        document.archived_by = archived_by

        audit_log = await self.audit_service.log_event(
            session,
            document_id=document.id,
            event_type=DocumentAuditEvent.ARCHIVED,
            actor_id=archived_by,
            actor_role="admin",
        )
        document.__dict__.setdefault("_audit_logs_cache", []).append(audit_log)

        await self.event_publisher.publish(
            event_type=DocumentAuditEvent.ARCHIVED.value,
            payload={
                "document_id": str(document.id),
                "entity_id": str(document.entity_id),
                "entity_type": document.entity_type.value,
            },
        )

        
        return document

    async def list_documents(
        self, session: AsyncSession, *, entity_id: UUID, entity_type: DocumentEntityType
    ) -> Sequence[Document]:
        result = await session.execute(
            select(Document)
            .options(selectinload(Document.audit_logs))
            .where(Document.entity_id == entity_id, Document.entity_type == entity_type)
        )
        return result.scalars().all()

    async def get_document(self, session: AsyncSession, document_id: UUID) -> Document:
        return await self._get_document(session, document_id)

    async def generate_download_url(
        self, session: AsyncSession, *, document_id: UUID, requestor_id: UUID
    ) -> tuple[Document, str]:
        document = await self._get_document(session, document_id)
        is_allowed = await self.access_control_service.is_authorized(
            user_id=requestor_id, action="document:download", resource_id=document.entity_id
        )
        if not is_allowed:
            raise PermissionError("Download not authorized")

        url = await self.storage_service.generate_presigned_url(
            document.storage_key, expires_in_seconds=settings.presigned_url_expiration_seconds
        )
        return document, url

    async def _get_document(self, session: AsyncSession, document_id: UUID) -> Document:
        result = await session.execute(select(Document).where(Document.id == document_id))
        document = result.scalar_one_or_none()
        if document is None:
            raise DocumentNotFoundError(f"Document {document_id} not found")
        return document
