from __future__ import annotations

import json
from collections.abc import Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, status, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_document_service
from app.core.config import settings
from app.db.session import get_db_session
from app.models.document import Document, DocumentAuditLog, DocumentEntityType, DocumentType
from app.schemas.document import (
    DocumentDeleteResponse,
    DocumentDownloadResponse,
    DocumentListResponse,
    DocumentMetadata,
    DocumentResponse,
    DocumentUploadMetadata,
    DocumentVerifyRequest,
)
from app.services.document_service import DocumentNotFoundError, DocumentService

router = APIRouter(prefix="/documents", tags=["documents"])


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
        metadata_payload = DocumentMetadata.model_validate(json.loads(metadata)) if metadata else None
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
        return DocumentResponse.from_model(document)
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
        await session.flush()
        await session.refresh(document)
        await session.commit()
        return DocumentResponse.from_model(document)
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
    return DocumentListResponse(documents=[DocumentResponse.from_model(doc, []) for doc in documents])


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