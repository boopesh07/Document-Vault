from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logger import get_logger
from app.models.document import DocumentAuditEvent, DocumentAuditLog

logger = get_logger(component="AuditService")


class AuditService:
    async def log_event(
        self,
        session: AsyncSession,
        *,
        document_id: UUID,
        event_type: DocumentAuditEvent,
        actor_id: UUID | None,
        actor_role: str | None = None,
        context: Mapping[str, Any] | None = None,
        notes: str | None = None,
    ) -> DocumentAuditLog:
        audit_log = DocumentAuditLog(
            document_id=document_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            context=dict(context) if context else None,
            notes=notes,
        )
        session.add(audit_log)
        await session.flush()
        logger.info(
            "Audit log recorded",
            document_id=str(document_id),
            event_type=event_type,
            actor_id=str(actor_id) if actor_id else None,
        )
        return audit_log
