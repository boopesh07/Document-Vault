from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.models.document import DocumentAuditEvent, DocumentEntityType, DocumentStatus, DocumentType
from app.models.types import GUID

revision = "20240601_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("entity_type", sa.Enum(DocumentEntityType, name="documententitytype"), nullable=False),
        sa.Column("entity_id", GUID(), nullable=False),
        sa.Column("token_id", sa.Integer(), nullable=True),
        sa.Column("document_type", sa.Enum(DocumentType, name="documenttype"), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("mime_type", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("storage_bucket", sa.String(length=63), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False, unique=True),
        sa.Column("storage_version_id", sa.String(length=255), nullable=True),
        sa.Column("sha256_hash", sa.String(length=128), nullable=False),
        sa.Column("hash_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Enum(DocumentStatus, name="documentstatus"), nullable=False),
        sa.Column("on_chain_reference", sa.String(length=255), nullable=True),
        sa.Column("uploaded_by", GUID(), nullable=False),
        sa.Column("verified_by", GUID(), nullable=True),
        sa.Column("archived_by", GUID(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )

    op.create_index(op.f("ix_documents_sha256_hash"), "documents", ["sha256_hash"], unique=False)

    op.create_table(
        "document_audit_logs",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("document_id", GUID(), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(DocumentAuditEvent, name="documentauditevent"),
            nullable=False,
        ),
        sa.Column("actor_id", GUID(), nullable=True),
        sa.Column("actor_role", sa.String(length=64), nullable=True),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.Column("notes", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(op.f("ix_document_audit_logs_document_id"), "document_audit_logs", ["document_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_document_audit_logs_document_id"), table_name="document_audit_logs")
    op.drop_table("document_audit_logs")
    op.drop_index(op.f("ix_documents_sha256_hash"), table_name="documents")
    op.drop_table("documents")
    sa.Enum(name="documentauditevent").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="documentstatus").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="documenttype").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="documententitytype").drop(op.get_bind(), checkfirst=False)
