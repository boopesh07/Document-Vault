"""Tests for Document Vault Consumer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.services.document_service import DocumentService
from app.workers.document_vault_consumer import DocumentVaultConsumer, EntityDeletedEvent


# ==================== Event Parsing Tests ====================


def test_entity_deleted_event_validation():
    """Test EntityDeletedEvent schema validation."""
    event_data = {
        "event_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
        "source": "entity_permissions_core",
        "action": "entity.deleted",
        "entity_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "entity_type": "issuer",
    }
    event = EntityDeletedEvent.model_validate(event_data)
    
    assert event.event_id == "a1b2c3d4-5678-90ab-cdef-1234567890ab"
    assert event.source == "entity_permissions_core"
    assert event.action == "entity.deleted"
    assert str(event.entity_id) == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert event.entity_type == "issuer"


def test_entity_deleted_event_missing_fields():
    """Test validation fails with missing required fields."""
    with pytest.raises(ValidationError):
        EntityDeletedEvent.model_validate({
            "event_id": "test-123",
            "source": "test",
            # Missing: action, entity_id, entity_type
        })


def test_parse_sns_wrapped_message():
    """Test parsing SQS message with SNS envelope."""
    import json
    
    sqs_message = {
        "MessageId": "msg-123",
        "ReceiptHandle": "receipt-456",
        "Body": json.dumps({
            "Type": "Notification",
            "Message": json.dumps({
                "event_id": "test-event-id",
                "source": "entity_permissions_core",
                "action": "entity.deleted",
                "entity_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "entity_type": "issuer",
            }),
        }),
    }
    
    event = DocumentVaultConsumer._parse_message(sqs_message)
    assert event.event_id == "test-event-id"
    assert event.action == "entity.deleted"


def test_parse_direct_sqs_message():
    """Test parsing direct SQS message (no SNS envelope)."""
    import json
    
    sqs_message = {
        "MessageId": "msg-123",
        "ReceiptHandle": "receipt-456",
        "Body": json.dumps({
            "event_id": "test-event-id",
            "source": "entity_permissions_core",
            "action": "entity.deleted",
            "entity_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "entity_type": "issuer",
        }),
    }
    
    event = DocumentVaultConsumer._parse_message(sqs_message)
    assert event.event_id == "test-event-id"
    assert event.action == "entity.deleted"


# ==================== Consumer Behavior Tests ====================


@pytest.mark.anyio("asyncio")
async def test_cascade_archive_by_entity():
    """Test cascade archival of documents for an entity."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.services.hashing_service import HashingService
    from app.services.storage_service import StorageService
    from app.events.publisher import DocumentEventPublisher
    
    entity_id = uuid4()
    user_id = uuid4()
    
    # Create mock documents
    doc1 = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="doc1.pdf",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="key1",
        sha256_hash="hash1",
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )
    
    doc2 = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.KYC,
        filename="doc2.pdf",
        mime_type="application/pdf",
        size_bytes=200,
        storage_bucket="test-bucket",
        storage_key="key2",
        sha256_hash="hash2",
        status=DocumentStatus.VERIFIED,
        uploaded_by=user_id,
    )
    
    # Mock dependencies
    mock_storage = MagicMock(spec=StorageService)
    mock_hashing = MagicMock(spec=HashingService)
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [doc1, doc2]
    mock_session.execute.return_value = mock_result
    
    # Create service
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )
    
    # Execute cascade archival
    archived_count = await document_service.cascade_archive_by_entity(
        mock_session,
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        archived_by=None,
    )
    
    # Verify results
    assert archived_count == 2
    assert doc1.status == DocumentStatus.ARCHIVED
    assert doc2.status == DocumentStatus.ARCHIVED
    assert doc1.archived_at is not None
    assert doc2.archived_at is not None
    
    # Verify audit events published (2 documents = 2 events)
    assert mock_audit_publisher.publish_event.call_count == 2
    
    # Verify document events published
    assert mock_event_publisher.publish.call_count == 2


@pytest.mark.anyio("asyncio")
async def test_deduplication_prevents_reprocessing():
    """Test that duplicate events are not reprocessed."""
    from app.models.processed_event import ProcessedEvent
    
    event_id = "test-event-123"
    
    # Mock session with existing processed event
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = ProcessedEvent(
        event_id=event_id,
        source="test",
        action="entity.deleted",
    )
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Check if duplicate
    is_duplicate = await DocumentVaultConsumer._is_duplicate(mock_session, event_id)
    
    assert is_duplicate is True


@pytest.mark.anyio("asyncio")
async def test_new_event_not_duplicate():
    """Test that new events are not marked as duplicates."""
    event_id = "new-event-456"
    
    # Mock session with no existing processed event
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Check if duplicate
    is_duplicate = await DocumentVaultConsumer._is_duplicate(mock_session, event_id)
    
    assert is_duplicate is False


# ==================== Integration Test ====================


@pytest.mark.anyio("asyncio")
async def test_consumer_full_flow_mock():
    """Integration test for consumer processing flow (mocked AWS)."""
    from app.services.audit_event_publisher import AuditEventPublisher
    from app.services.blockchain_service import BlockchainService
    from app.services.epr_service_mock import EprServiceMock
    from app.services.hashing_service import HashingService
    from app.services.storage_service import StorageService
    from app.events.publisher import DocumentEventPublisher
    
    # Create mocks
    mock_storage = MagicMock(spec=StorageService)
    mock_hashing = MagicMock(spec=HashingService)
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()
    
    document_service = DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )
    
    # Note: Full consumer integration test would require moto for SQS mocking
    # This is a placeholder demonstrating the structure
    
    assert document_service is not None
    assert hasattr(document_service, "cascade_archive_by_entity")

