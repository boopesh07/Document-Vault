from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, PrimaryKeyUUIDMixin, TimestampMixin


class ProcessedEvent(PrimaryKeyUUIDMixin, TimestampMixin, Base):
    """
    Tracks processed event IDs for deduplication.
    
    This table prevents duplicate processing of the same event from SQS,
    especially useful when messages are redelivered or duplicated.
    """
    __tablename__ = "document_vault_processed_events"

    event_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

