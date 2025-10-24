from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import aioboto3

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(component="EventPublisher")


class DocumentEventPublisher:
    def __init__(self) -> None:
        self._session = aioboto3.Session(profile_name=settings.aws_profile)

    async def publish(self, *, event_type: str, payload: dict[str, Any]) -> None:
        envelope = {
            "event_type": event_type,
            "occurred_at": datetime.now(tz=timezone.utc).isoformat(),
            "payload": payload,
        }
        body = json.dumps(envelope, separators=(",", ":"))
        async with self._session.client("sqs", region_name=settings.aws_region) as sqs_client:
            await sqs_client.send_message(
                QueueUrl=settings.document_events_queue_url,
                MessageBody=body,
                MessageAttributes={
                    "event_type": {"DataType": "String", "StringValue": event_type},
                },
            )
        logger.info("Event published", event_type=event_type)

    async def publish_integrity_alert(
        self,
        *,
        document_id: Any,
        filename: str,
        entity_id: Any,
        entity_type: Any,
        expected_hash: str,
        calculated_hash: str,
        verified_by: Any,
        severity: str = "CRITICAL",
        recommended_action: str = "FREEZE_ENTITY",
    ) -> None:
        """
        Publish an integrity alert to the compliance alert queue.
        
        This alert is triggered when a document hash mismatch is detected,
        indicating potential tampering. The alert is consumed by the compliance
        dashboard for immediate visibility and action.
        
        Args:
            document_id: UUID of the document with integrity issue
            filename: Name of the affected file
            entity_id: UUID of the entity owning the document
            entity_type: Type of entity (issuer, investor, etc.)
            expected_hash: Original SHA-256 hash from upload
            calculated_hash: Current SHA-256 hash (indicates tampering)
            verified_by: UUID of compliance officer who detected the issue
            severity: Alert severity level (default: CRITICAL)
            recommended_action: Recommended action (default: FREEZE_ENTITY)
        """
        alert_payload = {
            "alert_type": "integrity_violation",
            "severity": severity,
            "document_id": str(document_id),
            "filename": filename,
            "entity_id": str(entity_id),
            "entity_type": str(entity_type.value if hasattr(entity_type, 'value') else entity_type),
            "expected_hash": expected_hash,
            "calculated_hash": calculated_hash,
            "verified_by": str(verified_by),
            "recommended_action": recommended_action,
            "detected_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        
        body = json.dumps(alert_payload, separators=(",", ":"))
        
        # Publish to compliance alert queue (if configured)
        if settings.compliance_alert_queue_url:
            async with self._session.client("sqs", region_name=settings.aws_region) as sqs_client:
                await sqs_client.send_message(
                    QueueUrl=settings.compliance_alert_queue_url,
                    MessageBody=body,
                    MessageAttributes={
                        "alert_type": {"DataType": "String", "StringValue": "integrity_violation"},
                        "severity": {"DataType": "String", "StringValue": severity},
                    },
                )
            
            logger.warning(
                "Integrity alert published to compliance dashboard",
                alert_type="integrity_violation",
                document_id=str(document_id),
                entity_id=str(entity_id),
                severity=severity,
                verified_by=str(verified_by),
            )
        else:
            logger.warning(
                "Integrity alert detected but compliance alert queue not configured",
                document_id=str(document_id),
                entity_id=str(entity_id),
            )
