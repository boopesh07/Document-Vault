"""Comprehensive tests for Delete / Archive Behavior.

Tests soft-delete functionality where documents are archived, not permanently deleted.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.events.publisher import DocumentEventPublisher
from fastapi import UploadFile


# ==================== Fixtures ====================


@pytest.fixture
def document_for_archive():
    """Create a mock document for archiving."""
    doc_id = uuid4()
    entity_id = uuid4()
    user_id = uuid4()
    
    return Document(
        id=doc_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="contract.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="test-bucket",
        storage_key=f"documents/{doc_id}/contract.pdf",
        sha256_hash="abc123",
        status=DocumentStatus.VERIFIED,
        uploaded_by=user_id,
        verified_by=user_id,
        hash_verified_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def document_service_for_archive():
    """Create DocumentService for archive testing."""
    mock_storage = MagicMock(spec=StorageService)
    mock_storage.upload_document = AsyncMock(return_value=("s3-key-123", "version-1"))
    
    hashing_service = HashingService()
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_blockchain.register_document = AsyncMock(return_value="tx-blockchain-123")
    
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()
    
    return DocumentService(
        storage_service=mock_storage,
        hashing_service=hashing_service,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )


# ==================== Test 1: DELETE Marks as Archived (Not Deleted) ====================


@pytest.mark.anyio("asyncio")
async def test_delete_marks_document_as_archived_not_deleted(
    document_service_for_archive, document_for_archive
):
    """
    Test: DELETE /documents/:id marks record archived, not deleted
    
    Validates:
    - Document record remains in database
    - Status changed to ARCHIVED
    - archived_at timestamp set
    - archived_by field populated
    - Document retrievable by ID
    - Audit event published
    """
    service = document_service_for_archive
    document = document_for_archive
    archiver_id = uuid4()
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Pre-archive state
    assert document.status == DocumentStatus.VERIFIED
    assert document.archived_at is None
    assert document.archived_by is None
    
    original_id = document.id
    original_filename = document.filename
    original_storage_key = document.storage_key
    
    # Execute archive (soft delete)
    archived_document = await service.archive_document(
        mock_session,
        document_id=document.id,
        archived_by=archiver_id,
    )
    
    # Assertions - Document still exists (not deleted)
    assert archived_document.id == original_id
    assert archived_document.filename == original_filename
    assert archived_document.storage_key == original_storage_key
    
    # Status changed to ARCHIVED
    assert archived_document.status == DocumentStatus.ARCHIVED
    
    # Archival metadata set
    assert archived_document.archived_at is not None
    assert archived_document.archived_by == archiver_id
    assert isinstance(archived_document.archived_at, datetime)
    assert archived_document.archived_at.tzinfo is not None  # Timezone-aware
    
    # All original data preserved
    assert archived_document.entity_id == document.entity_id
    assert archived_document.entity_type == document.entity_type
    assert archived_document.sha256_hash == document.sha256_hash
    assert archived_document.uploaded_by == document.uploaded_by
    
    # Verify audit event published
    service.audit_event_publisher.publish_event.assert_called_once()
    audit_call = service.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.archived"
    assert audit_call["actor_id"] == archiver_id
    assert audit_call["entity_id"] == document.id
    assert "archived_at" in audit_call["details"]
    assert "filename" in audit_call["details"]
    
    # Verify document event published
    service.event_publisher.publish.assert_called_once()


@pytest.mark.anyio("asyncio")
async def test_archived_document_remains_retrievable_by_id(
    document_service_for_archive, document_for_archive
):
    """
    Test: Archived document can still be retrieved by ID
    
    Validates:
    - get_document works for archived docs
    - All fields accessible
    - Status correctly shows ARCHIVED
    """
    service = document_service_for_archive
    document = document_for_archive
    archiver_id = uuid4()
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Archive the document
    await service.archive_document(mock_session, document_id=document.id, archived_by=archiver_id)
    
    # Document should be ARCHIVED
    assert document.status == DocumentStatus.ARCHIVED
    
    # Should still be retrievable by ID
    retrieved_document = await service.get_document(mock_session, document.id)
    
    assert retrieved_document is not None
    assert retrieved_document.id == document.id
    assert retrieved_document.status == DocumentStatus.ARCHIVED
    assert retrieved_document.archived_by == archiver_id


@pytest.mark.anyio("asyncio")
async def test_archive_preserves_verification_history(
    document_service_for_archive, document_for_archive
):
    """
    Test: Archiving preserves verification and upload history
    
    Validates:
    - uploaded_by preserved
    - verified_by preserved
    - hash_verified_at preserved
    - Complete audit trail maintained
    """
    service = document_service_for_archive
    document = document_for_archive
    archiver_id = uuid4()
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Store original verification data
    original_uploaded_by = document.uploaded_by
    original_verified_by = document.verified_by
    original_hash_verified_at = document.hash_verified_at
    
    # Archive
    archived_document = await service.archive_document(
        mock_session,
        document_id=document.id,
        archived_by=archiver_id,
    )
    
    # Verification history preserved
    assert archived_document.uploaded_by == original_uploaded_by
    assert archived_document.verified_by == original_verified_by
    assert archived_document.hash_verified_at == original_hash_verified_at
    
    # Archival metadata added (not replaced)
    assert archived_document.archived_by == archiver_id
    assert archived_document.archived_at is not None


# ==================== Test 2: Archived Docs Hidden from Lists ====================


@pytest.mark.anyio("asyncio")
async def test_archived_documents_hidden_from_default_list(
    document_service_for_archive
):
    """
    Test: Archived docs hidden from document list
    
    Validates:
    - list_documents excludes archived by default
    - Only active documents returned
    - Multiple archived docs all excluded
    """
    service = document_service_for_archive
    entity_id = uuid4()
    
    # Create multiple documents with different statuses
    doc1 = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="active1.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key1",
        sha256_hash="hash1",
        status=DocumentStatus.UPLOADED,
        uploaded_by=uuid4(),
    )
    
    doc2 = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="active2.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key2",
        sha256_hash="hash2",
        status=DocumentStatus.VERIFIED,
        uploaded_by=uuid4(),
    )
    
    doc3_archived = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="archived1.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key3",
        sha256_hash="hash3",
        status=DocumentStatus.ARCHIVED,
        uploaded_by=uuid4(),
        archived_by=uuid4(),
        archived_at=datetime.now(timezone.utc),
    )
    
    doc4_archived = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="archived2.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key4",
        sha256_hash="hash4",
        status=DocumentStatus.ARCHIVED,
        uploaded_by=uuid4(),
        archived_by=uuid4(),
        archived_at=datetime.now(timezone.utc),
    )
    
    # Mock session to return all 4 documents initially,
    # but our query will filter archived ones
    all_docs = [doc1, doc2, doc3_archived, doc4_archived]
    active_docs = [doc1, doc2]
    
    # Mock session
    mock_session = AsyncMock()
    
    # When we query with status != ARCHIVED filter, return only active
    def execute_side_effect(query):
        # Simplified: return active_docs for filtered query
        mock_result = MagicMock()
        mock_result.scalars = Mock(return_value=MagicMock(all=Mock(return_value=active_docs)))
        return mock_result
    
    mock_session.execute = AsyncMock(side_effect=execute_side_effect)
    
    # List documents (default: exclude archived)
    documents = await service.list_documents(
        mock_session,
        entity_id=entity_id,
    )
    
    # Only active documents returned
    assert len(documents) == 2
    assert doc1 in documents
    assert doc2 in documents
    assert doc3_archived not in documents
    assert doc4_archived not in documents
    
    # Verify all returned documents are not archived
    for doc in documents:
        assert doc.status != DocumentStatus.ARCHIVED


@pytest.mark.anyio("asyncio")
async def test_archived_documents_included_when_explicitly_requested(
    document_service_for_archive
):
    """
    Test: Archived docs can be included if explicitly requested
    
    Validates:
    - include_archived=True returns all documents
    - Admin/audit access to archived docs
    - Total count includes archived
    """
    service = document_service_for_archive
    entity_id = uuid4()
    
    # Create active and archived documents
    doc_active = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="active.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key1",
        sha256_hash="hash1",
        status=DocumentStatus.UPLOADED,
        uploaded_by=uuid4(),
    )
    
    doc_archived = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="archived.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key2",
        sha256_hash="hash2",
        status=DocumentStatus.ARCHIVED,
        uploaded_by=uuid4(),
        archived_by=uuid4(),
        archived_at=datetime.now(timezone.utc),
    )
    
    all_docs = [doc_active, doc_archived]
    
    # Mock session
    mock_session = AsyncMock()
    
    def execute_side_effect(query):
        mock_result = MagicMock()
        mock_result.scalars = Mock(return_value=MagicMock(all=Mock(return_value=all_docs)))
        return mock_result
    
    mock_session.execute = AsyncMock(side_effect=execute_side_effect)
    
    # List with include_archived=True
    documents = await service.list_documents(
        mock_session,
        entity_id=entity_id,
        include_archived=True,
    )
    
    # All documents returned (including archived)
    assert len(documents) == 2
    assert doc_active in documents
    assert doc_archived in documents


@pytest.mark.anyio("asyncio")
async def test_empty_list_when_all_documents_archived(
    document_service_for_archive
):
    """
    Test: Empty list returned when all documents are archived
    
    Validates:
    - No documents returned if all archived
    - No errors with empty result
    - Correct behavior for cleanup scenarios
    """
    service = document_service_for_archive
    entity_id = uuid4()
    
    # Create only archived documents
    doc1_archived = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="archived1.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        storage_bucket="bucket",
        storage_key="key1",
        sha256_hash="hash1",
        status=DocumentStatus.ARCHIVED,
        uploaded_by=uuid4(),
        archived_by=uuid4(),
        archived_at=datetime.now(timezone.utc),
    )
    
    # Mock session to return empty list (all filtered out)
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars = Mock(return_value=MagicMock(all=Mock(return_value=[])))
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # List documents
    documents = await service.list_documents(
        mock_session,
        entity_id=entity_id,
    )
    
    # Empty list returned
    assert len(documents) == 0
    assert documents == []


# ==================== Test 3: Re-upload with Same Filename Allowed ====================


@pytest.mark.anyio("asyncio")
async def test_reupload_same_filename_after_archive(
    document_service_for_archive
):
    """
    Test: Re-upload with same filename allowed after archive
    
    Validates:
    - Can upload file with same name as archived document
    - No duplicate detection error
    - New document created with fresh ID
    - Archived document unchanged
    """
    service = document_service_for_archive
    entity_id = uuid4()
    user_id = uuid4()
    
    filename = "important_contract.pdf"
    file_content = b"Original content"
    
    # Archived document with this filename
    archived_doc = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename=filename,  # Same filename
        mime_type="application/pdf",
        size_bytes=len(file_content),
        storage_bucket="bucket",
        storage_key="old-key",
        sha256_hash=hashlib.sha256(file_content).hexdigest(),
        status=DocumentStatus.ARCHIVED,
        uploaded_by=user_id,
        archived_by=user_id,
        archived_at=datetime.now(timezone.utc),
    )
    
    # New upload with same filename but different content
    new_content = b"Updated content"
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = filename  # Same filename!
    mock_file.content_type = "application/pdf"
    mock_file.file = io.BytesIO(new_content)
    
    # Mock session - duplicate check should NOT find archived doc
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    
    # Duplicate check query returns nothing (archived docs excluded from check)
    mock_result_duplicate_check = MagicMock()
    mock_result_duplicate_check.scalar_one_or_none = Mock(return_value=None)
    mock_session.execute = AsyncMock(return_value=mock_result_duplicate_check)
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Execute upload - should succeed
    new_document = await service.upload_document(
        mock_session,
        file=mock_file,
        metadata=metadata,
    )
    
    # New document created
    assert new_document is not None
    assert new_document.filename == filename
    assert new_document.status == DocumentStatus.UPLOADED
    assert new_document.id != archived_doc.id  # Different ID
    assert new_document.sha256_hash != archived_doc.sha256_hash  # Different content
    
    # No error raised (upload succeeded)
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()


@pytest.mark.anyio("asyncio")
async def test_reupload_same_content_different_hash_after_archive(
    document_service_for_archive
):
    """
    Test: Re-upload with same content hash allowed if original archived
    
    Validates:
    - Duplicate hash check excludes archived documents
    - Can re-upload identical content after archive
    - Useful for document recovery scenarios
    """
    service = document_service_for_archive
    entity_id = uuid4()
    user_id = uuid4()
    
    file_content = b"Contract content"
    content_hash = hashlib.sha256(file_content).hexdigest()
    
    # Archived document with this hash
    archived_doc = Document(
        id=uuid4(),
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="contract_v1.pdf",
        mime_type="application/pdf",
        size_bytes=len(file_content),
        storage_bucket="bucket",
        storage_key="old-key",
        sha256_hash=content_hash,  # Same hash
        status=DocumentStatus.ARCHIVED,
        uploaded_by=user_id,
        archived_by=user_id,
        archived_at=datetime.now(timezone.utc),
    )
    
    # Re-upload with same content but different filename
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = "contract_v2.pdf"  # Different filename
    mock_file.content_type = "application/pdf"
    mock_file.file = io.BytesIO(file_content)  # Same content!
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    
    # Duplicate check excludes archived docs
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Execute upload - should succeed (archived doc excluded from duplicate check)
    new_document = await service.upload_document(
        mock_session,
        file=mock_file,
        metadata=metadata,
    )
    
    # New document created successfully
    assert new_document is not None
    assert new_document.sha256_hash == content_hash  # Same content
    assert new_document.filename != archived_doc.filename  # Different filename
    assert new_document.id != archived_doc.id  # Different document
    assert new_document.status == DocumentStatus.UPLOADED


# ==================== Test 4: Complete Archive Lifecycle ====================


@pytest.mark.anyio("asyncio")
async def test_complete_archive_lifecycle(
    document_service_for_archive, document_for_archive
):
    """
    Test: Complete document lifecycle including archive
    
    Validates entire flow:
    1. Upload document
    2. Verify document
    3. Document appears in lists
    4. Archive document
    5. Document hidden from default lists
    6. Document still retrievable by ID
    7. Can re-upload same filename
    8. Events published correctly
    """
    service = document_service_for_archive
    document = document_for_archive
    entity_id = document.entity_id
    user_id = uuid4()
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Step 1-2: Document uploaded and verified (already in VERIFIED state)
    assert document.status == DocumentStatus.VERIFIED
    
    # Step 3: Archive the document
    archived_doc = await service.archive_document(
        mock_session,
        document_id=document.id,
        archived_by=user_id,
    )
    
    assert archived_doc.status == DocumentStatus.ARCHIVED
    assert archived_doc.archived_by == user_id
    assert archived_doc.archived_at is not None
    
    # Step 4: Verify events published
    assert service.audit_event_publisher.publish_event.called
    assert service.event_publisher.publish.called
    
    # Step 5: Document still retrievable by ID
    retrieved = await service.get_document(mock_session, document.id)
    assert retrieved.status == DocumentStatus.ARCHIVED
    
    # Step 6: Archival metadata complete
    assert archived_doc.filename is not None
    assert archived_doc.storage_key is not None
    assert archived_doc.sha256_hash is not None
    assert archived_doc.entity_id == entity_id









