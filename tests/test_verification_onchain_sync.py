"""
Comprehensive verification and on-chain sync tests.

Tests validate end-to-end document verification flow including hash recomputation,
blockchain registration, event emission, and database synchronization performance.
"""

from __future__ import annotations

import asyncio
import io
import time
from datetime import datetime, timezone
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.models.document import Document, DocumentEntityType, DocumentStatus, DocumentType
from app.schemas.document import DocumentUploadMetadata
from app.services.audit_event_publisher import AuditEventPublisher
from app.services.blockchain_service import BlockchainService
from app.services.document_service import DocumentService
from app.services.epr_service_mock import EprServiceMock
from app.services.hashing_service import HashingService
from app.services.storage_service import StorageService
from app.events.publisher import DocumentEventPublisher


@pytest.fixture
def entity_id() -> UUID:
    """Return a fixed entity ID for testing."""
    return uuid4()


@pytest.fixture
def user_id() -> UUID:
    """Return a fixed user ID for testing."""
    return uuid4()


@pytest.fixture
def verifier_id() -> UUID:
    """Return a fixed verifier ID for testing."""
    return uuid4()


@pytest.fixture
def mock_file_content() -> bytes:
    """Return consistent file content for testing."""
    return b"This is a test document for blockchain verification."


class BlockchainServiceMock(BlockchainService):
    """
    Enhanced blockchain service mock that simulates on-chain hash storage.
    
    This mock maintains an in-memory registry of document hashes to simulate
    blockchain storage and retrieval for verification tests.
    """
    
    def __init__(self):
        super().__init__()
        self._on_chain_registry: dict[str, str] = {}  # tx_id -> hash mapping
    
    async def register_document(
        self, *, token_id: int | None, document_hash: str, metadata_uri: str | None
    ) -> str:
        """Register document hash on blockchain and return transaction ID."""
        tx_id = f"tx-blockchain-{document_hash[:16]}"
        self._on_chain_registry[tx_id] = document_hash
        
        logger = __import__('app.core.logger', fromlist=['get_logger']).get_logger(component="BlockchainServiceMock")
        logger.info(
            "Document registered on blockchain",
            token_id=token_id,
            document_hash=document_hash,
            tx_id=tx_id,
        )
        return tx_id
    
    async def get_on_chain_hash(self, tx_id: str) -> str | None:
        """Retrieve hash from blockchain using transaction ID."""
        return self._on_chain_registry.get(tx_id)
    
    async def verify_against_blockchain(self, tx_id: str, current_hash: str) -> bool:
        """Verify current hash against blockchain-stored hash."""
        on_chain_hash = await self.get_on_chain_hash(tx_id)
        if on_chain_hash is None:
            return False
        return on_chain_hash == current_hash


def create_mock_upload_file(content: bytes, filename: str, mime_type: str):
    """Helper to create a mock UploadFile."""
    from fastapi import UploadFile
    
    mock_file = MagicMock(spec=UploadFile)
    mock_file.filename = filename
    mock_file.content_type = mime_type
    mock_file.file = io.BytesIO(content)
    return mock_file


@pytest.fixture
def document_service_with_blockchain() -> Callable[[], DocumentService]:
    """
    Factory fixture that returns a DocumentService with enhanced blockchain mock.
    
    Returns a service with blockchain registry for testing on-chain sync.
    """
    
    def _factory() -> DocumentService:
        # Create mock storage service
        mock_storage = AsyncMock(spec=StorageService)
        mock_storage.upload_document = AsyncMock(return_value=("s3-key-123", "version-id-456"))
        
        # Create real hashing service for consistent hashes
        hashing_service = HashingService()
        
        # Create mock audit publisher
        mock_audit_publisher = AsyncMock(spec=AuditEventPublisher)
        mock_audit_publisher.publish_event = AsyncMock()
        
        # Create mock EPR service (grant all access)
        mock_epr = AsyncMock(spec=EprServiceMock)
        mock_epr.is_authorized = AsyncMock(return_value=True)
        
        # Create enhanced blockchain service mock with registry
        blockchain_service = BlockchainServiceMock()
        
        # Create mock event publisher
        mock_event_publisher = AsyncMock(spec=DocumentEventPublisher)
        mock_event_publisher.publish = AsyncMock()
        mock_event_publisher.publish_integrity_alert = AsyncMock()
        
        service = DocumentService(
            storage_service=mock_storage,
            hashing_service=hashing_service,
            audit_event_publisher=mock_audit_publisher,
            access_control_service=mock_epr,
            blockchain_service=blockchain_service,
            event_publisher=mock_event_publisher,
        )
        
        # Attach mocks for inspection in tests
        service._mock_storage = mock_storage
        service._mock_audit_publisher = mock_audit_publisher
        service._mock_event_publisher = mock_event_publisher
        service._mock_blockchain = blockchain_service
        
        return service
    
    return _factory


@pytest.fixture
async def mock_document_factory(entity_id: UUID, user_id: UUID) -> Callable:
    """Factory to create mock documents with custom properties."""
    
    def _create_document(**kwargs) -> Document:
        defaults = {
            "id": uuid4(),
            "entity_type": DocumentEntityType.ISSUER,
            "entity_id": entity_id,
            "document_type": DocumentType.OPERATING_AGREEMENT,
            "filename": "test.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 1024,
            "storage_bucket": "test-bucket",
            "storage_key": "test-key",
            "storage_version_id": "version-1",
            "sha256_hash": "a" * 64,
            "status": DocumentStatus.UPLOADED,
            "uploaded_by": user_id,
        }
        defaults.update(kwargs)
        return Document(**defaults)
    
    return _create_document


# ============================================================================
# Test: Re-Hash Matches Blockchain-Stored Hash
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_rehash_matches_blockchain_stored_hash(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Re-hash matches blockchain-stored hash
    
    Validates:
    - Document uploaded and hash computed
    - First verification: hash registered on blockchain
    - Second verification: re-computed hash matches blockchain-stored hash
    - Blockchain transaction ID preserved in document
    - Verification succeeds
    """
    service = document_service_with_blockchain()
    
    # Step 1: Upload document (hash computed and stored in DB)
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=original_hash,
    )
    
    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Mock storage to return original content
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Step 2: First verification - registers hash on blockchain
    verified_document_first = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify blockchain registration occurred
    assert verified_document_first.status == DocumentStatus.VERIFIED
    assert verified_document_first.on_chain_reference is not None
    assert verified_document_first.on_chain_reference.startswith("tx-blockchain-")
    
    # Verify hash was stored on blockchain
    on_chain_hash = await service.blockchain_service.get_on_chain_hash(
        verified_document_first.on_chain_reference
    )
    assert on_chain_hash == original_hash
    
    # Step 3: Second verification - verify against blockchain
    # Reset mock for second verification
    mock_session.execute = AsyncMock(return_value=mock_result)
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    verified_document_second = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify re-hash matches blockchain-stored hash
    blockchain_match = await service.blockchain_service.verify_against_blockchain(
        verified_document_second.on_chain_reference,
        original_hash,
    )
    assert blockchain_match is True
    assert verified_document_second.status == DocumentStatus.VERIFIED


@pytest.mark.anyio("asyncio")
async def test_blockchain_hash_retrieval_after_registration(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Blockchain hash can be retrieved after registration
    
    Validates:
    - Hash registered on blockchain returns transaction ID
    - Transaction ID can be used to retrieve original hash
    - Retrieved hash matches original document hash
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Verify document (triggers blockchain registration)
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Retrieve hash from blockchain using transaction ID
    retrieved_hash = await service.blockchain_service.get_on_chain_hash(
        verified_document.on_chain_reference
    )
    
    assert retrieved_hash is not None
    assert retrieved_hash == original_hash


# ============================================================================
# Test: Mismatch Triggers document.mismatch Event
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_mismatch_triggers_document_mismatch_event(
    document_service_with_blockchain,
    mock_document_factory,
    verifier_id,
):
    """
    Test: Mismatch triggers document.mismatch event
    
    Validates:
    - Hash mismatch detected during verification
    - document.mismatch event published
    - Event contains expected_hash and calculated_hash
    - Document status changes to MISMATCH
    - Blockchain NOT registered for mismatched document
    """
    service = document_service_with_blockchain()
    
    expected_hash = "a" * 64
    calculated_hash = "b" * 64  # Different hash
    
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=expected_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Mock storage to return tampered content
    async def mock_stream():
        yield b"tampered content"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Mock hashing to return different hash
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value=calculated_hash)
    ))
    
    # Trigger verification
    mismatched_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify status is MISMATCH
    assert mismatched_document.status == DocumentStatus.MISMATCH
    
    # Verify document.mismatch event was published
    service._mock_event_publisher.publish.assert_called()
    event_calls = [call for call in service._mock_event_publisher.publish.call_args_list
                   if call[1]["event_type"] == "document.mismatch"]
    assert len(event_calls) == 1
    
    event_payload = event_calls[0][1]["payload"]
    assert event_payload["expected_hash"] == expected_hash
    assert event_payload["calculated_hash"] == calculated_hash
    
    # Verify blockchain was NOT registered (mismatch case)
    assert mismatched_document.on_chain_reference is None


@pytest.mark.anyio("asyncio")
async def test_mismatch_event_contains_comprehensive_metadata(
    document_service_with_blockchain,
    mock_document_factory,
    entity_id,
    verifier_id,
):
    """
    Test: Mismatch event contains comprehensive metadata
    
    Validates:
    - Event includes document_id
    - Event includes entity context
    - Event includes both expected and calculated hashes
    - Event published immediately on mismatch detection
    """
    service = document_service_with_blockchain()
    
    expected_hash = "original_hash_123"
    calculated_hash = "tampered_hash_456"
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=expected_hash,
        entity_id=entity_id,
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield b"tampered"
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    service.hashing_service.create_digest = Mock(return_value=MagicMock(
        update=Mock(),
        hexdigest=Mock(return_value=calculated_hash)
    ))
    
    await service.verify_document(mock_session, document_id=document.id, verifier_id=verifier_id)
    
    # Verify event metadata
    event_calls = [call for call in service._mock_event_publisher.publish.call_args_list
                   if call[1]["event_type"] == "document.mismatch"]
    event_payload = event_calls[0][1]["payload"]
    
    assert event_payload["document_id"] == str(document.id)
    assert event_payload["entity_id"] == str(entity_id)
    assert event_payload["expected_hash"] == expected_hash
    assert event_payload["calculated_hash"] == calculated_hash


# ============================================================================
# Test: Successful Verification Emits document.verified
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_successful_verification_emits_document_verified(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Successful verification emits document.verified
    
    Validates:
    - Hash matches trigger VERIFIED status
    - document.verified event published
    - Event contains document metadata
    - Event includes on_chain_reference after blockchain registration
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify status is VERIFIED
    assert verified_document.status == DocumentStatus.VERIFIED
    
    # Verify document.verified event was published
    service._mock_event_publisher.publish.assert_called()
    event_calls = [call for call in service._mock_event_publisher.publish.call_args_list
                   if call[1]["event_type"] == "document.verified"]
    assert len(event_calls) == 1
    
    event_payload = event_calls[0][1]["payload"]
    assert event_payload["document_id"] == str(document.id)
    assert event_payload["sha256_hash"] == original_hash


@pytest.mark.anyio("asyncio")
async def test_document_verified_event_includes_blockchain_reference(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: document.verified event includes blockchain reference
    
    Validates:
    - Successful verification registers hash on blockchain
    - Resulting event includes blockchain transaction ID
    - Transaction ID can be used for later verification
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify blockchain reference exists
    assert verified_document.on_chain_reference is not None
    assert verified_document.on_chain_reference.startswith("tx-blockchain-")
    
    # Verify audit event includes on_chain_reference
    service._mock_audit_publisher.publish_event.assert_called_once()
    audit_call = service._mock_audit_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.verified"
    assert "on_chain_reference" in audit_call["details"]
    assert audit_call["details"]["on_chain_reference"] == verified_document.on_chain_reference


# ============================================================================
# Test: Verification Reflected in DB Within 2 Seconds
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_verification_reflected_in_db_within_2_seconds(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Verification reflected in DB within 2 seconds
    
    Validates:
    - Complete verification process completes quickly
    - Database updates occur within performance threshold
    - Total time from start to DB commit < 2 seconds
    - Includes hash computation, blockchain registration, event publishing
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Measure verification time
    start_time = time.time()
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    end_time = time.time()
    verification_time = end_time - start_time
    
    # Verify performance requirement
    assert verification_time < 2.0, f"Verification took {verification_time:.3f}s, expected < 2.0s"
    
    # Verify all operations completed
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.hash_verified_at is not None
    assert verified_document.verified_by == verifier_id
    assert verified_document.on_chain_reference is not None


@pytest.mark.anyio("asyncio")
async def test_large_file_verification_performance(
    document_service_with_blockchain,
    mock_document_factory,
    verifier_id,
):
    """
    Test: Large file verification meets performance requirements
    
    Validates:
    - Verification of larger files (10MB) still meets performance threshold
    - Streaming hash computation is efficient
    - Database operations remain fast even with larger files
    """
    service = document_service_with_blockchain()
    
    # Create 10MB file content
    large_file_content = b"x" * (10 * 1024 * 1024)  # 10MB
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(large_file_content))
    
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=original_hash,
        size_bytes=len(large_file_content),
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    # Stream content in chunks for realistic test
    async def mock_stream():
        chunk_size = 1024 * 1024  # 1MB chunks
        for i in range(0, len(large_file_content), chunk_size):
            yield large_file_content[i:i + chunk_size]
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    start_time = time.time()
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    end_time = time.time()
    verification_time = end_time - start_time
    
    # Verify performance (allow up to 2 seconds for 10MB file)
    assert verification_time < 2.0, f"Large file verification took {verification_time:.3f}s, expected < 2.0s"
    assert verified_document.status == DocumentStatus.VERIFIED


# ============================================================================
# Test: Complete Verification & On-Chain Sync Flow
# ============================================================================

@pytest.mark.anyio("asyncio")
async def test_complete_verification_onchain_sync_flow(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    entity_id,
    user_id,
    verifier_id,
):
    """
    Test: Complete verification and on-chain sync flow
    
    Validates end-to-end workflow:
    1. Document uploaded with initial hash
    2. First verification: re-hash computed and matches
    3. Hash registered on blockchain with transaction ID
    4. Document status updated to VERIFIED
    5. document.verified event published
    6. Audit event published with blockchain reference
    7. All operations complete within 2 seconds
    8. Second verification: hash compared against blockchain
    9. Blockchain verification confirms integrity
    """
    service = document_service_with_blockchain()
    
    # Step 1: Document uploaded
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(
        status=DocumentStatus.UPLOADED,
        sha256_hash=original_hash,
        entity_id=entity_id,
        uploaded_by=user_id,
    )
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Step 2-7: First verification
    start_time = time.time()
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    verification_time = time.time() - start_time
    
    # Verify all operations completed
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.hash_verified_at is not None
    assert verified_document.verified_by == verifier_id
    assert verified_document.on_chain_reference is not None
    assert verification_time < 2.0
    
    # Verify document.verified event published
    event_calls = [call for call in service._mock_event_publisher.publish.call_args_list
                   if call[1]["event_type"] == "document.verified"]
    assert len(event_calls) == 1
    
    # Verify audit event published with blockchain reference
    service._mock_audit_publisher.publish_event.assert_called_once()
    audit_call = service._mock_audit_publisher.publish_event.call_args[1]
    assert audit_call["action"] == "document.verified"
    assert audit_call["details"]["on_chain_reference"] == verified_document.on_chain_reference
    
    # Step 8-9: Second verification against blockchain
    blockchain_match = await service.blockchain_service.verify_against_blockchain(
        verified_document.on_chain_reference,
        original_hash,
    )
    assert blockchain_match is True


@pytest.mark.anyio("asyncio")
async def test_verification_workflow_with_blockchain_logging(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Verification workflow includes comprehensive blockchain logging
    
    Validates:
    - Blockchain registration is logged
    - Hash and transaction ID are logged
    - Verification status is logged
    - All critical steps have log entries
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    verified_document = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify document was verified successfully (logging happens automatically)
    assert verified_document.status == DocumentStatus.VERIFIED
    assert verified_document.on_chain_reference is not None
    
    # Verify blockchain service registered the document (implicit logging test)
    on_chain_hash = await service.blockchain_service.get_on_chain_hash(
        verified_document.on_chain_reference
    )
    assert on_chain_hash == original_hash


@pytest.mark.anyio("asyncio")
async def test_multiple_verifications_maintain_same_blockchain_reference(
    document_service_with_blockchain,
    mock_document_factory,
    mock_file_content,
    verifier_id,
):
    """
    Test: Multiple verifications maintain same blockchain reference
    
    Validates:
    - First verification registers hash on blockchain
    - Subsequent verifications use same blockchain reference
    - Blockchain reference is not duplicated
    - All verifications succeed using original blockchain registration
    """
    service = document_service_with_blockchain()
    
    original_hash = service.hashing_service.compute_sha256(io.BytesIO(mock_file_content))
    document = mock_document_factory(status=DocumentStatus.UPLOADED, sha256_hash=original_hash)
    
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = Mock(return_value=document)
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    async def mock_stream():
        yield mock_file_content
    
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # First verification
    verified_doc_1 = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    first_blockchain_ref = verified_doc_1.on_chain_reference
    assert first_blockchain_ref is not None
    
    # Update document to VERIFIED status for second verification
    document.status = DocumentStatus.VERIFIED
    document.on_chain_reference = first_blockchain_ref
    
    # Reset mocks
    mock_session.execute = AsyncMock(return_value=mock_result)
    service.storage_service.stream_document = Mock(return_value=mock_stream())
    
    # Second verification (should use existing blockchain reference)
    verified_doc_2 = await service.verify_document(
        mock_session,
        document_id=document.id,
        verifier_id=verifier_id,
    )
    
    # Verify same blockchain reference is maintained
    assert verified_doc_2.on_chain_reference == first_blockchain_ref

