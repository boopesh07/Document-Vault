from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logger import get_logger
from app.models.audit import AuditLog
from app.models.document import Document, DocumentAuditEvent

logger = get_logger(component="AuditService")


class AuditService:
    async def log_event(
        self,
        session: AsyncSession,
        *,
        document: Document,
        event_type: DocumentAuditEvent,
        actor_id: UUID | None,
        actor_role: str | None = None,
        context: Mapping[str, Any] | None = None,
        notes: str | None = None,
    ) -> AuditLog:
        details: dict[str, Any] = {}
        if context:
            details["context"] = dict(context)
        if notes:
            details["notes"] = notes

        audit_log = AuditLog(
            actor_id=actor_id,
            actor_type=actor_role or "user",
            entity_id=document.id,
            entity_type=document.document_type.value,
            action=event_type.value,
            details=details,
        )
        session.add(audit_log)
        logger.info(
            "Audit log recorded",
            document_id=str(document.id),
            event_type=event_type,
            actor_id=str(actor_id) if actor_id else None,
        )
        return audit_log
