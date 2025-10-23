"""SQS consumer for entity deletion events that cascade document archival."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

import aioboto3
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.logger import get_logger
from app.db.session import AsyncSessionFactory
from app.models.document import DocumentEntityType
from app.models.processed_event import ProcessedEvent
from app.services.document_service import DocumentService

logger = get_logger(component="DocumentVaultConsumer")


class EntityDeletedEvent(BaseModel):
    """Schema for entity.deleted events from EPR service."""

    event_id: str = Field(..., description="Unique event identifier for deduplication")
    source: str = Field(..., description="Source system that emitted the event")
    action: str = Field(..., description="Action type (e.g., entity.deleted)")
    entity_id: UUID = Field(..., description="UUID of the entity being deleted")
    entity_type: str = Field(..., description="Type of entity (issuer, investor, deal, etc.)")


class DocumentVaultConsumer:
    """
    Long-polling SQS consumer that processes entity deletion events and cascades document archival.

    This consumer listens to the EPR_DOCUMENT_VAULT_TOPIC_ARN SNS topic via an SQS queue.
    When an entity is deleted, it archives all associated documents in a transactional manner.

    Features:
    - Deduplication via processed_events table
    - Transactional processing (rollback on failure)
    - Long-polling for efficiency
    - Graceful shutdown support
    """

    def __init__(
        self,
        *,
        queue_url: str,
        document_service: DocumentService,
        region_name: str | None = None,
        wait_time_seconds: int = 20,
        visibility_timeout: int | None = None,
        max_messages: int = 5,
    ) -> None:
        self._queue_url = queue_url
        self._document_service = document_service
        self._wait_time_seconds = wait_time_seconds
        self._max_messages = max_messages
        self._region_name = region_name
        self._visibility_timeout = visibility_timeout
        self._session = aioboto3.Session(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            aws_session_token=settings.aws_session_token,
            region_name=region_name,
        )
        self._running = False
        self._shutdown_event = asyncio.Event()

    async def run_forever(self) -> None:
        """Start the consumer and process messages until shutdown is requested."""
        self._running = True
        logger.info("Starting Document Vault consumer", queue_url=self._queue_url)

        try:
            while self._running:
                try:
                    await self._process_batch()
                except asyncio.CancelledError:
                    logger.info("Consumer task cancelled, shutting down gracefully")
                    break
                except Exception as exc:
                    logger.exception("Unexpected error in consumer loop", error=str(exc))
                    await asyncio.sleep(5)  # Brief pause before retrying
        finally:
            logger.info("Document Vault consumer stopped")
            self._shutdown_event.set()

    async def shutdown(self) -> None:
        """Signal the consumer to stop processing and wait for graceful shutdown."""
        logger.info("Shutdown requested for Document Vault consumer")
        self._running = False
        await self._shutdown_event.wait()

    async def _process_batch(self) -> None:
        """Receive and process a batch of messages from SQS."""
        async with self._session.client("sqs", region_name=self._region_name) as sqs_client:
            receive_kwargs: dict[str, Any] = {
                "QueueUrl": self._queue_url,
                "MaxNumberOfMessages": self._max_messages,
                "WaitTimeSeconds": self._wait_time_seconds,
                "MessageAttributeNames": ["All"],
            }
            if self._visibility_timeout is not None:
                receive_kwargs["VisibilityTimeout"] = self._visibility_timeout

            response = await sqs_client.receive_message(**receive_kwargs)
            messages = response.get("Messages", [])

            if not messages:
                return  # No messages, continue polling

            for message in messages:
                receipt_handle = message["ReceiptHandle"]
                message_id = message.get("MessageId")

                try:
                    event = self._parse_message(message)
                    await self._process_event(event, message_id=message_id)

                    # Only acknowledge after successful processing
                    await sqs_client.delete_message(QueueUrl=self._queue_url, ReceiptHandle=receipt_handle)
                    logger.info("Message acknowledged and deleted", message_id=message_id, event_id=event.event_id)

                except ValidationError as exc:
                    logger.error("Invalid event payload, discarding message", error=str(exc), message_id=message_id)
                    # Delete invalid messages to prevent queue pollution
                    await sqs_client.delete_message(QueueUrl=self._queue_url, ReceiptHandle=receipt_handle)

                except Exception as exc:
                    logger.exception(
                        "Failed to process message, will retry after visibility timeout",
                        error=str(exc),
                        message_id=message_id,
                    )
                    # Do NOT delete message - it will become visible again for retry

    @staticmethod
    def _parse_message(message: dict[str, Any]) -> EntityDeletedEvent:
        """
        Parse SQS message body, handling both direct SQS and SNS-wrapped messages.

        SNS messages have an envelope structure with the actual event in the "Message" field.
        """
        body = message.get("Body", "")
        payload: dict[str, Any]

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in message body: {exc}") from exc

        # Handle SNS envelope
        if payload and "Message" in payload:
            inner = payload["Message"]
            if isinstance(inner, str):
                event_payload = json.loads(inner)
            else:
                event_payload = inner
        else:
            event_payload = payload

        return EntityDeletedEvent.model_validate(event_payload)

    async def _process_event(self, event: EntityDeletedEvent, *, message_id: str | None) -> None:
        """
        Process an entity.deleted event by cascading document archival.

        This method is transactional - if any step fails, the entire operation is rolled back,
        and the message remains in the queue for retry.
        """
        async with AsyncSessionFactory() as session:
            try:
                # Check for duplicate (deduplication)
                is_duplicate = await self._is_duplicate(session, event.event_id)
                if is_duplicate:
                    logger.warning(
                        "Duplicate event detected, skipping processing",
                        event_id=event.event_id,
                        message_id=message_id,
                    )
                    await session.commit()
                    return

                # Validate entity type
                try:
                    entity_type_enum = DocumentEntityType(event.entity_type.lower())
                except ValueError:
                    logger.warning(
                        "Unsupported entity type, skipping",
                        entity_type=event.entity_type,
                        event_id=event.event_id,
                    )
                    # Mark as processed to avoid reprocessing
                    await self._mark_processed(session, event)
                    await session.commit()
                    return

                # Cascade archive all documents for this entity
                archived_count = await self._document_service.cascade_archive_by_entity(
                    session,
                    entity_id=event.entity_id,
                    entity_type=entity_type_enum,
                    archived_by=None,  # System-initiated archival
                )

                # Mark event as processed (deduplication record)
                await self._mark_processed(session, event)

                # Commit transaction - only reaches here if all operations succeed
                await session.commit()

                logger.info(
                    "Successfully processed entity deletion event",
                    event_id=event.event_id,
                    entity_id=str(event.entity_id),
                    entity_type=event.entity_type,
                    archived_count=archived_count,
                    message_id=message_id,
                )

            except Exception as exc:
                await session.rollback()
                logger.exception(
                    "Failed to process event, transaction rolled back",
                    event_id=event.event_id,
                    error=str(exc),
                )
                raise  # Re-raise to prevent message acknowledgment

    @staticmethod
    async def _is_duplicate(session, event_id: str) -> bool:
        """Check if this event has already been processed."""
        result = await session.execute(select(ProcessedEvent).where(ProcessedEvent.event_id == event_id))
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def _mark_processed(session, event: EntityDeletedEvent) -> None:
        """Record that this event has been processed (for deduplication)."""
        processed_event = ProcessedEvent(
            event_id=event.event_id,
            source=event.source,
            action=event.action,
            entity_id=str(event.entity_id),
            entity_type=event.entity_type,
        )
        session.add(processed_event)
        try:
            await session.flush()
        except IntegrityError:
            # Race condition: another instance already processed this event
            logger.info("Event already marked as processed by another instance", event_id=event.event_id)
            await session.rollback()


def build_consumer_from_env(document_service: DocumentService) -> DocumentVaultConsumer | None:
    """
    Factory that reads configuration from environment variables.

    Returns None if the consumer is disabled or not configured.
    """
    if not settings.enable_document_consumer:
        logger.info("Document Vault consumer is disabled via ENABLE_DOCUMENT_CONSUMER")
        return None

    if not settings.document_vault_sqs_url:
        logger.warning("Document Vault consumer enabled but DOCUMENT_VAULT_SQS_URL not configured")
        return None

    return DocumentVaultConsumer(
        queue_url=settings.document_vault_sqs_url,
        document_service=document_service,
        region_name=settings.aws_region,
        max_messages=settings.document_consumer_max_messages,
        wait_time_seconds=settings.document_consumer_wait_time,
        visibility_timeout=settings.document_consumer_visibility_timeout,
    )

