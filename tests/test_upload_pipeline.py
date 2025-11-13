"""Comprehensive tests for File Upload -> Hash -> Store Pipeline."""

from __future__ import annotations

import hashlib
import io
import time
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import (
    DocumentService,
    DuplicateDocumentError,
    FileSizeExceededError,
    InvalidFileTypeError,
)
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.events.publisher import DocumentEventPublisher


# ==================== Fixtures ====================


@pytest.fixture
def valid_pdf_content():
    """Generate valid PDF-like content."""
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + b"test content for PDF" * 100


@pytest.fixture
def large_file_content():
    """Generate content larger than max file size (105MB, default max is 100MB)."""
    return b"x" * (105 * 1024 * 1024)


@pytest.fixture
def mock_upload_file():
    """Create a mock UploadFile."""
    def _create_file(content: bytes, filename: str = "test.pdf", content_type: str = "application/pdf"):
        from fastapi import UploadFile
        
        mock_file = MagicMock(spec=UploadFile)
        mock_file.filename = filename
        mock_file.content_type = content_type
        mock_file.file = io.BytesIO(content)
        return mock_file
    
    return _create_file


@pytest.fixture
def document_service_with_mocks():
    """Create DocumentService with all dependencies mocked."""
    mock_storage = MagicMock(spec=StorageService)
    mock_storage.upload_document = AsyncMock(return_value=("s3-key-123", "version-1"))
    
    mock_hashing = HashingService()  # Use real hashing service
    
    mock_audit_publisher = MagicMock(spec=AuditEventPublisher)
    mock_audit_publisher.publish_event = AsyncMock()
    
    mock_epr = MagicMock(spec=EprServiceMock)
    mock_epr.is_authorized = AsyncMock(return_value=True)
    
    mock_blockchain = MagicMock(spec=BlockchainService)
    mock_event_publisher = MagicMock(spec=DocumentEventPublisher)
    mock_event_publisher.publish = AsyncMock()
    
    return DocumentService(
        storage_service=mock_storage,
        hashing_service=mock_hashing,
        audit_event_publisher=mock_audit_publisher,
        access_control_service=mock_epr,
        blockchain_service=mock_blockchain,
        event_publisher=mock_event_publisher,
    )


# ==================== Test 1: Valid File Stored in S3 and Metadata Created ====================


@pytest.mark.anyio("asyncio")
async def test_valid_file_stored_and_metadata_created(
    document_service_with_mocks, mock_upload_file, valid_pdf_content
):
    """
    Test: Valid file stored in mock S3 and metadata created in DB
    
    Validates:
    - File successfully uploaded to S3
    - Document metadata persisted in database
    - Storage key and version ID captured
    - All document fields populated correctly
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Create mock file
    file = mock_upload_file(valid_pdf_content, "agreement.pdf", "application/pdf")
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)  # No duplicate
    mock_session.execute.return_value = mock_result
    
    # Execute upload
    document = await document_service_with_mocks.upload_document(
        mock_session, file=file, metadata=metadata
    )
    
    # Assertions
    assert document is not None
    assert document.filename == "agreement.pdf"
    assert document.mime_type == "application/pdf"
    assert document.size_bytes == len(valid_pdf_content)
    assert document.storage_key == "s3-key-123"
    assert document.storage_version_id == "version-1"
    assert document.status == DocumentStatus.UPLOADED
    assert document.uploaded_by == user_id
    assert document.entity_id == entity_id
    assert len(document.sha256_hash) == 64  # SHA-256 produces 64-char hex string
    
    # Verify S3 upload called
    document_service_with_mocks.storage_service.upload_document.assert_called_once()
    
    # Verify document added to session
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()


# ==================== Test 2: Hash Integrity ====================


@pytest.mark.anyio("asyncio")
async def test_hash_integrity_between_upload_and_db(
    document_service_with_mocks, mock_upload_file, valid_pdf_content
):
    """
    Test: Hash integrity confirmed between upload and DB record
    
    Validates:
    - SHA-256 hash computed correctly
    - Hash in DB matches file content hash
    - Hash computation is deterministic
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Compute expected hash
    expected_hash = hashlib.sha256(valid_pdf_content).hexdigest()
    
    # Create mock file
    file = mock_upload_file(valid_pdf_content)
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)
    mock_session.execute.return_value = mock_result
    
    # Execute upload
    document = await document_service_with_mocks.upload_document(
        mock_session, file=file, metadata=metadata
    )
    
    # Verify hash integrity
    assert document.sha256_hash == expected_hash
    
    # Verify hash is consistent (upload same file again, should get same hash)
    file2 = mock_upload_file(valid_pdf_content)
    
    document2 = await document_service_with_mocks.upload_document(
        mock_session, file=file2, metadata=metadata
    )
    
    assert document2.sha256_hash == expected_hash
    assert document.sha256_hash == document2.sha256_hash


# ==================== Test 3: Duplicate Detection ====================


@pytest.mark.anyio("asyncio")
async def test_duplicate_file_upload_detected(
    document_service_with_mocks, mock_upload_file, valid_pdf_content
):
    """
    Test: Duplicate file uploads detected
    
    Validates:
    - Duplicate detection works by hash
    - DuplicateDocumentError raised with proper message
    - Includes existing document ID in error
    """
    entity_id = uuid4()
    user_id = uuid4()
    existing_doc_id = uuid4()
    
    # Create mock file
    file = mock_upload_file(valid_pdf_content)
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Compute hash for duplicate check
    file_hash = hashlib.sha256(valid_pdf_content).hexdigest()
    
    # Create existing document
    existing_document = Document(
        id=existing_doc_id,
        entity_type=DocumentEntityType.ISSUER,
        entity_id=entity_id,
        document_type=DocumentType.OPERATING_AGREEMENT,
        filename="existing.pdf",
        mime_type="application/pdf",
        size_bytes=len(valid_pdf_content),
        storage_bucket="test-bucket",
        storage_key="existing-key",
        sha256_hash=file_hash,
        status=DocumentStatus.UPLOADED,
        uploaded_by=user_id,
    )
    
    # Mock session with existing duplicate
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=existing_document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Execute upload and expect duplicate error
    with pytest.raises(DuplicateDocumentError) as exc_info:
        await document_service_with_mocks.upload_document(
            mock_session, file=file, metadata=metadata
        )
    
    # Verify error message
    assert str(existing_doc_id) in str(exc_info.value)
    assert "already exists" in str(exc_info.value).lower()


# ==================== Test 4: Invalid MIME Type Rejection ====================


@pytest.mark.anyio("asyncio")
async def test_invalid_mime_type_rejected(
    document_service_with_mocks, mock_upload_file
):
    """
    Test: Invalid MIME type rejected
    
    Validates:
    - Executable files rejected (.exe)
    - Script files rejected (.sh)
    - InvalidFileTypeError raised with proper message
    - Lists allowed MIME types in error
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Test various invalid MIME types
    invalid_mime_types = [
        ("malware.exe", "application/x-msdownload"),
        ("script.sh", "application/x-sh"),
        ("binary.bin", "application/octet-stream"),
        ("archive.zip", "application/zip"),
    ]
    
    for filename, mime_type in invalid_mime_types:
        # Create mock file with invalid MIME type
        file = mock_upload_file(b"malicious content", filename, mime_type)
        
        # Create upload metadata
        metadata = DocumentUploadMetadata(
            entity_id=entity_id,
            entity_type=DocumentEntityType.ISSUER,
            document_type=DocumentType.OPERATING_AGREEMENT,
            uploaded_by=user_id,
        )
        
        # Mock session
        mock_session = AsyncMock()
        
        # Execute upload and expect error
        with pytest.raises(InvalidFileTypeError) as exc_info:
            await document_service_with_mocks.upload_document(
                mock_session, file=file, metadata=metadata
            )
        
        # Verify error message
        assert mime_type in str(exc_info.value)
        assert "not allowed" in str(exc_info.value).lower()
        assert "application/pdf" in str(exc_info.value)  # Lists allowed types


# ==================== Test 5: Oversized File Rejection ====================


@pytest.mark.anyio("asyncio")
async def test_oversized_file_rejected(
    document_service_with_mocks, mock_upload_file, large_file_content
):
    """
    Test: Oversized file rejected
    
    Validates:
    - Files larger than max size rejected
    - FileSizeExceededError raised with proper message
    - Error includes file size and limit in human-readable format
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Create oversized file (105MB)
    file = mock_upload_file(large_file_content, "huge.pdf", "application/pdf")
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    
    # Execute upload and expect error
    with pytest.raises(FileSizeExceededError) as exc_info:
        await document_service_with_mocks.upload_document(
            mock_session, file=file, metadata=metadata
        )
    
    # Verify error message
    error_message = str(exc_info.value)
    assert "exceeds maximum" in error_message.lower()
    assert "100" in error_message or "104857600" in error_message  # Max size mentioned
    assert "105" in error_message or str(len(large_file_content)) in error_message  # Actual size mentioned


# ==================== Test 6: Upload Latency ====================


@pytest.mark.anyio("asyncio")
async def test_upload_latency_under_one_second(
    document_service_with_mocks, mock_upload_file, valid_pdf_content
):
    """
    Test: Upload latency < 1s
    
    Validates:
    - End-to-end upload completes in < 1 second
    - Measures time from upload call to completion
    - Uses realistic file size (few KB)
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Create mock file with realistic size
    file = mock_upload_file(valid_pdf_content)
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)
    mock_session.execute.return_value = mock_result
    
    # Measure upload time
    start_time = time.time()
    
    document = await document_service_with_mocks.upload_document(
        mock_session, file=file, metadata=metadata
    )
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Verify latency
    assert elapsed_time < 1.0, f"Upload took {elapsed_time:.3f}s, expected < 1.0s"
    assert document is not None


# ==================== Test 7: Complete Pipeline Validation ====================


@pytest.mark.anyio("asyncio")
async def test_complete_upload_pipeline_validation(
    document_service_with_mocks, mock_upload_file, valid_pdf_content
):
    """
    Test: Complete end-to-end pipeline validation
    
    Validates entire pipeline in sequence:
    1. File validation (MIME type + size)
    2. Hash computation (SHA-256)
    3. Duplicate detection
    4. S3 storage
    5. Metadata persistence
    6. Event emission (audit + document events)
    """
    entity_id = uuid4()
    user_id = uuid4()
    
    # Create mock file
    file = mock_upload_file(valid_pdf_content, "complete_test.pdf", "application/pdf")
    
    # Create upload metadata
    metadata = DocumentUploadMetadata(
        entity_id=entity_id,
        entity_type=DocumentEntityType.ISSUER,
        document_type=DocumentType.OPERATING_AGREEMENT,
        uploaded_by=user_id,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_session.add = Mock()
    mock_session.flush = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=None)  # No duplicate
    mock_session.execute.return_value = mock_result
    
    # Execute upload
    document = await document_service_with_mocks.upload_document(
        mock_session, file=file, metadata=metadata
    )
    
    # Validate complete pipeline
    
    # 1. File validation passed (no exception raised)
    assert document is not None
    
    # 2. Hash computed correctly
    expected_hash = hashlib.sha256(valid_pdf_content).hexdigest()
    assert document.sha256_hash == expected_hash
    assert len(document.sha256_hash) == 64
    
    # 3. Duplicate check performed
    mock_session.execute.assert_called()
    
    # 4. S3 storage called
    document_service_with_mocks.storage_service.upload_document.assert_called_once()
    call_args = document_service_with_mocks.storage_service.upload_document.call_args
    assert call_args[1]["filename"] == "complete_test.pdf"
    assert call_args[1]["mime_type"] == "application/pdf"
    
    # 5. Metadata persisted
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()
    assert document.filename == "complete_test.pdf"
    assert document.mime_type == "application/pdf"
    assert document.size_bytes == len(valid_pdf_content)
    assert document.storage_key == "s3-key-123"
    
    # 6. Events emitted
    document_service_with_mocks.audit_event_publisher.publish_event.assert_called_once()
    document_service_with_mocks.event_publisher.publish.assert_called_once()
    
    # Verify audit event
    audit_call = document_service_with_mocks.audit_event_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.uploaded"
    assert audit_call["actor_id"] == user_id
    
    # Verify document event
    doc_event_call = document_service_with_mocks.event_publisher.publish.call_args[1]
    assert doc_event_call["event_type"] == "document.uploaded"
    assert "sha256_hash" in doc_event_call["payload"]


# ==================== Test 8: Allowed MIME Types ====================


@pytest.mark.anyio("asyncio")
async def test_all_allowed_mime_types_accepted(
    document_service_with_mocks, mock_upload_file
):
    """
    Test: All configured allowed MIME types are accepted
    
    Validates:
    - PDF files accepted
    - Word documents accepted
    - Excel files accepted
    - Images (JPEG, PNG) accepted
    - Text files accepted
    """
    from app.core.config import settings
    
    entity_id = uuid4()
    user_id = uuid4()
    
    # Test each allowed MIME type
    for mime_type in settings.allowed_mime_types:
        # Map MIME type to appropriate filename
        filename_map = {
            "application/pdf": "document.pdf",
            "application/msword": "document.doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document.docx",
            "application/vnd.ms-excel": "spreadsheet.xls",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "spreadsheet.xlsx",
            "text/plain": "document.txt",
            "image/jpeg": "image.jpg",
            "image/png": "image.png",
        }
        
        filename = filename_map.get(mime_type, "file.bin")
        content = b"test content for " + mime_type.encode()
        
        # Create mock file
        file = mock_upload_file(content, filename, mime_type)
        
        # Create upload metadata
        metadata = DocumentUploadMetadata(
            entity_id=entity_id,
            entity_type=DocumentEntityType.ISSUER,
            document_type=DocumentType.OPERATING_AGREEMENT,
            uploaded_by=user_id,
        )
        
        # Mock session
        mock_session = AsyncMock()
        mock_session.add = Mock()
        mock_session.flush = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = Mock(return_value=None)
        mock_session.execute.return_value = mock_result
        
        # Execute upload - should not raise exception
        document = await document_service_with_mocks.upload_document(
            mock_session, file=file, metadata=metadata
        )
        
        assert document is not None
        assert document.mime_type == mime_type









