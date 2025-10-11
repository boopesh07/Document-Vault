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
