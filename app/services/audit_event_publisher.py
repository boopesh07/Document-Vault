from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import httpx

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="AuditEventPublisher")


class AuditEventPublisher:
    """Publishes audit events to the centralized EPR service API."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client

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
        Publish an audit event to the centralized EPR service API.

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
        if not settings.epr_service_url:
            logger.error("EPR_SERVICE_URL not configured. Cannot publish audit event.")
            return

        # The example correlation_id is "document_vault:doc_123:verification"
        # We'll construct it from the available data.
        if entity_id:
            short_action = action.split(".")[-1]
            built_correlation_id = f"document_vault:{entity_id}:{short_action}"
        else:
            built_correlation_id = f"document_vault:{uuid4()}:{action}"

        payload = {
            "event_type": action,
            "source": "document_vault",
            "payload": details or {},
            "context": {
                "actor_id": str(actor_id) if actor_id else None,
                "actor_type": actor_type,
                "entity_id": str(entity_id) if entity_id else None,
                "entity_type": entity_type,
            },
            "correlation_id": correlation_id or built_correlation_id,
        }

        base_url = str(settings.epr_service_url).rstrip("/")

        try:
            response = await self.http_client.post(
                f"{base_url}/api/v1/events",
                json=payload,
                timeout=settings.epr_service_timeout,
            )

            if response.status_code == 201:
                response_data = response.json()
                delivery_state = response_data.get("delivery_state")
                if delivery_state == "failed":
                    logger.error(
                        "Audit event delivery failed after API call",
                        action=action,
                        correlation_id=payload["correlation_id"],
                        error=response_data.get("last_error"),
                    )
                else:
                    logger.info(
                        "Audit event published to API",
                        action=action,
                        correlation_id=payload["correlation_id"],
                        delivery_state=delivery_state,
                    )
            else:
                logger.error(
                    "Failed to publish audit event via API",
                    action=action,
                    status_code=response.status_code,
                    response=response.text,
                )
        except httpx.RequestError as e:
            logger.exception(
                "Error publishing audit event via API",
                action=action,
                error=str(e),
            )







