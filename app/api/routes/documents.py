from __future__ import annotations

import json
from collections.abc import Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_document_service
from app.core.config import settings
from app.db.session import get_db_session
from app.models.document import Document, DocumentAuditLog, DocumentEntityType, DocumentType
from app.schemas.document import (
    DocumentDeleteResponse,
    DocumentDownloadResponse,
    DocumentListResponse,
    DocumentResponse,
    DocumentUploadMetadata,
    DocumentVerifyRequest,
    DocumentAuditLogEntry,
)
from app.services.document_service import DocumentNotFoundError, DocumentService

router = APIRouter(prefix="/documents", tags=["documents"])


def _to_document_response(
    document: Document, audit_logs: Sequence[DocumentAuditLog] | None = None
) -> DocumentResponse:
    if audit_logs is not None:
        logs_source = list(audit_logs)
    else:
        logs_source = list(getattr(document, "_audit_logs_cache", []))
    audit_logs_payload = [
        DocumentAuditLogEntry.model_validate(log, from_attributes=True) for log in logs_source
    ]
    return DocumentResponse(
        id=document.id,
        entity_type=document.entity_type,
        entity_id=document.entity_id,
        token_id=document.token_id,
        document_type=document.document_type,
        filename=document.filename,
        mime_type=document.mime_type,
        size_bytes=document.size_bytes,
        storage_bucket=document.storage_bucket,
        storage_key=document.storage_key,
        sha256_hash=document.sha256_hash,
        status=document.status,
        uploaded_by=document.uploaded_by,
        verified_by=document.verified_by,
        archived_by=document.archived_by,
        archived_at=document.archived_at,
        hash_verified_at=document.hash_verified_at,
        on_chain_reference=document.on_chain_reference,
        metadata=document.metadata_json,
        created_at=document.created_at,
        updated_at=document.updated_at,
        audit_logs=audit_logs_payload if audit_logs_payload else None,
    )


@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    entity_id: UUID = Form(...),
    entity_type: DocumentEntityType = Form(...),
    document_type: DocumentType = Form(...),
    uploaded_by: UUID = Form(...),
    token_id: int | None = Form(default=None),
    metadata: str | None = Form(default=None),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        metadata_payload = json.loads(metadata) if metadata else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="metadata must be valid JSON") from exc

    upload_metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=entity_type,
        document_type=document_type,
        uploaded_by=uploaded_by,
        token_id=token_id,
        metadata=metadata_payload,
    )

    try:
        document = await document_service.upload_document(session, file=file, metadata=upload_metadata)
        await session.commit()
        return _to_document_response(document)
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.post("/verify", response_model=DocumentResponse)
async def verify_document(
    payload: DocumentVerifyRequest,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.verify_document(
            session, document_id=payload.document_id, verifier_id=payload.verifier_id
        )
        await session.commit()
        return _to_document_response(document)
    except DocumentNotFoundError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise


@router.get("/{entity_id}", response_model=DocumentListResponse)
async def list_documents(
    entity_id: UUID,
    entity_type: DocumentEntityType,
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    documents = await document_service.list_documents(session, entity_id=entity_id, entity_type=entity_type)
    return DocumentListResponse(documents=[_to_document_response(doc, []) for doc in documents])


@router.get("/{document_id}/download", response_model=DocumentDownloadResponse)
async def generate_download_url(
    document_id: UUID,
    requestor_id: UUID = Query(...),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document, url = await document_service.generate_download_url(
            session, document_id=document_id, requestor_id=requestor_id
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return DocumentDownloadResponse(
        document_id=document.id,
        download_url=url,
        expires_in_seconds=settings.presigned_url_expiration_seconds,
    )


@router.delete("/{document_id}", response_model=DocumentDeleteResponse)
async def archive_document(
    document_id: UUID,
    archived_by: UUID = Query(...),
    session: AsyncSession = Depends(get_db_session),
    document_service: DocumentService = Depends(get_document_service),
):
    try:
        document = await document_service.archive_document(
            session, document_id=document_id, archived_by=archived_by
        )
        await session.commit()
        return DocumentDeleteResponse(
            document_id=document.id,
            status=document.status,
            archived_at=document.archived_at,
        )
    except DocumentNotFoundError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise
