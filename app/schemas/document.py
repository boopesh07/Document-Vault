from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.document import DocumentAuditEvent, DocumentEntityType, DocumentStatus, DocumentType


class DocumentMetadata(BaseModel):
    description: str | None = None
    tags: list[str] | None = None
    extra: dict[str, Any] | None = None


class DocumentUploadMetadata(BaseModel):
    entity_id: UUID
    entity_type: DocumentEntityType
    document_type: DocumentType
    uploaded_by: UUID
    token_id: int | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def ensure_dict(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        raise TypeError("metadata must be a JSON object")


class DocumentVerifyRequest(BaseModel):
    document_id: UUID
    verifier_id: UUID


class DocumentDownloadResponse(BaseModel):
    document_id: UUID
    download_url: str
    expires_in_seconds: int


class DocumentAuditLogEntry(BaseModel):
    id: UUID
    event_type: DocumentAuditEvent
    actor_id: UUID | None
    actor_role: str | None
    notes: str | None
    context: dict[str, Any] | None
    created_at: datetime


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    entity_type: DocumentEntityType
    entity_id: UUID
    token_id: int | None
    document_type: DocumentType
    filename: str
    mime_type: str
    size_bytes: int
    storage_bucket: str
    storage_key: str
    sha256_hash: str
    status: DocumentStatus
    uploaded_by: UUID
    verified_by: UUID | None
    archived_by: UUID | None
    archived_at: datetime | None
    hash_verified_at: datetime | None
    on_chain_reference: str | None
    metadata: dict[str, Any] | None = Field(default=None, alias="metadata_json")
    created_at: datetime
    updated_at: datetime
    audit_logs: list[DocumentAuditLogEntry] | None = None


class DocumentListResponse(BaseModel):
    documents: list[DocumentResponse]


class DocumentDeleteResponse(BaseModel):
    document_id: UUID
    status: DocumentStatus
    archived_at: datetime | None
