from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import aioboto3

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="AuditEventPublisher")


class AuditEventPublisher:
    """Publishes audit events to the centralized SNS topic consumed by EPR service."""

    def __init__(self) -> None:
        self._session = aioboto3.Session(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            aws_session_token=settings.aws_session_token,
            region_name=settings.aws_region,
        )

    async def publish_event(
        self,
        *,
        action: str,
        actor_id: UUID | None,
        actor_type: str = "user",
        entity_id: UUID | None = None,
        entity_type: str | None = None,
        details: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        event_id: UUID | None = None,
    ) -> None:
        """
        Publish an audit event to the centralized SNS topic.

        Args:
            action: The action being performed (e.g., "document.uploaded")
            actor_id: UUID of the user/system performing the action
            actor_type: Type of actor (default: "user")
            entity_id: UUID of the entity being acted upon
            entity_type: Type of entity (e.g., "document")
            details: Optional JSON metadata about the event
            correlation_id: Optional correlation ID for tracing
            event_id: Optional event ID for idempotency (auto-generated if not provided)
        """
        payload = {
            "event_id": str(event_id or uuid4()),
            "source": "document-vault-service",
            "action": action,
            "actor_id": str(actor_id) if actor_id else None,
            "actor_type": actor_type,
            "entity_id": str(entity_id) if entity_id else None,
            "entity_type": entity_type,
            "correlation_id": correlation_id,
            "details": details or {},
            "occurred_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        message_body = json.dumps(payload, separators=(",", ":"))

        async with self._session.client("sns", region_name=settings.aws_region) as sns_client:
            await sns_client.publish(
                TopicArn=settings.audit_sns_topic_arn,
                Message=message_body,
                MessageAttributes={
                    "action": {"DataType": "String", "StringValue": action},
                    "source": {"DataType": "String", "StringValue": "document-vault-service"},
                },
            )

        logger.info(
            "Audit event published to SNS",
            action=action,
            event_id=payload["event_id"],
            entity_id=str(entity_id) if entity_id else None,
            actor_id=str(actor_id) if actor_id else None,
        )

