from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import JSON, Enum as SAEnum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import DateTime

from app.models.base import Base, PrimaryKeyUUIDMixin, TimestampMixin
from app.models.types import GUID


class DocumentStatus(str, PyEnum):
    UPLOADED = "uploaded"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    ARCHIVED = "archived"


class DocumentEntityType(str, PyEnum):
    ISSUER = "issuer"
    INVESTOR = "investor"
    DEAL = "deal"
    TOKEN = "token"
    COMPLIANCE = "compliance"


class DocumentType(str, PyEnum):
    OPERATING_AGREEMENT = "operating_agreement"
    OFFERING_MEMORANDUM = "offering_memorandum"
    SUBSCRIPTION = "subscription"
    KYC = "kyc"
    AUDIT_REPORT = "audit_report"
    OTHER = "other"


class Document(PrimaryKeyUUIDMixin, TimestampMixin, Base):
    __tablename__ = "documents"

    entity_type: Mapped[DocumentEntityType] = mapped_column(
        SAEnum(DocumentEntityType, name="documententitytype", native_enum=False)
    )
    entity_id: Mapped[Any] = mapped_column(GUID(), nullable=False)
    token_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    document_type: Mapped[DocumentType] = mapped_column(
        SAEnum(DocumentType, name="documenttype", native_enum=False)
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    storage_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    storage_version_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    sha256_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    hash_verified_at: Mapped[datetime | None] = mapped_column(nullable=True)

    status: Mapped[DocumentStatus] = mapped_column(
        SAEnum(DocumentStatus, name="documentstatus", native_enum=False),
        nullable=False,
        default=DocumentStatus.UPLOADED,
    )
    on_chain_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)

    uploaded_by: Mapped[Any] = mapped_column(GUID(), nullable=False)
    verified_by: Mapped[Any | None] = mapped_column(GUID(), nullable=True)
    archived_by: Mapped[Any | None] = mapped_column(GUID(), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(nullable=True)

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON, nullable=True)

    audit_logs: Mapped[list["DocumentAuditLog"]] = relationship(
        "DocumentAuditLog", back_populates="document", cascade="all, delete-orphan"
    )



class DocumentAuditEvent(str, PyEnum):
    UPLOAD = "document.uploaded"
    VERIFIED = "document.verified"
    MISMATCH = "document.mismatch"
    ARCHIVED = "document.archived"
    REHASH_REQUESTED = "document.rehash_requested"


class DocumentAuditLog(PrimaryKeyUUIDMixin, Base):
    __tablename__ = "document_audit_logs"

    document_id: Mapped[Any] = mapped_column(GUID(), ForeignKey("documents.id"), nullable=False, index=True)
    event_type: Mapped[DocumentAuditEvent] = mapped_column(
        SAEnum(DocumentAuditEvent, name="documentauditevent", native_enum=False)
    )
    actor_id: Mapped[Any | None] = mapped_column(GUID(), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    document: Mapped["Document"] = relationship("Document", back_populates="audit_logs")
