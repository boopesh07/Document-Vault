from __future__ import annotations

import uuid

from sqlalchemy import Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin
from app.models.types import GUID, JSONType


class AuditLog(TimestampMixin, Base):
    """Immutable audit log entries."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_actor", "actor_id"),
        Index("ix_audit_logs_entity", "entity_id"),
        Index("ix_audit_logs_action", "action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(length=64), nullable=False, default="user")
    entity_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(length=64), nullable=True)
    action: Mapped[str] = mapped_column(String(length=120), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(length=120), nullable=True)
    details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
