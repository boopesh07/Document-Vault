from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import AsyncMock
import pytest


@pytest.mark.anyio("asyncio")
async def test_document_upload_verify_and_archive_flow(async_client, aws_environment):
    entity_id = uuid4()
    uploader_id = uuid4()
    document_id = uuid4()
    
    mock_document_service = aws_environment["mock_document_service"]

    # 1. Mock the upload response
    mock_document_service.upload_document = AsyncMock(
        return_value=SimpleNamespace(
            id=document_id,
            status="uploaded",
            filename="agreement.pdf",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            entity_type="issuer",
            entity_id=entity_id,
            token_id=1,
            document_type="operating_agreement",
            mime_type="application/pdf",
            size_bytes=100,
            storage_bucket="test-bucket",
            storage_key="test-key",
            sha256_hash="test-hash",
            uploaded_by=uploader_id,
            verified_by=None,
            archived_by=None,
            archived_at=None,
            hash_verified_at=None,
            on_chain_reference=None,
            metadata_json={"description": "Operating agreement"},
        )
    )

    response = await async_client.post(
        "/api/v1/documents/upload",
        data={
            "entity_id": str(entity_id),
            "entity_type": "issuer",
            "document_type": "operating_agreement",
            "uploaded_by": str(uploader_id),
            "token_id": "1",
            "metadata": '{"description": "Operating agreement"}',
        },
        files={"file": ("agreement.pdf", b"dummy-pdf-data", "application/pdf")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["id"] == str(document_id)
    assert body["status"] == "uploaded"
    assert body["filename"] == "agreement.pdf"

    # 2. Mock the verify response
    # The response model requires the full document, so we mock all necessary fields.
    verified_document_mock = SimpleNamespace(
        id=document_id,
        status="verified",
        filename="agreement.pdf",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        entity_type="issuer",
        entity_id=entity_id,
        token_id=1,
        document_type="operating_agreement",
        mime_type="application/pdf",
        size_bytes=100,
        storage_bucket="test-bucket",
        storage_key="test-key",
        sha256_hash="test-hash",
        uploaded_by=uploader_id,
        verified_by=uploader_id,
        archived_by=None,
        archived_at=None,
        hash_verified_at=datetime.now(timezone.utc),
        on_chain_reference="tx-123",
        metadata_json={"description": "Operating agreement"},
    )
    mock_document_service.verify_document = AsyncMock(return_value=verified_document_mock)

    verify_resp = await async_client.post(
        "/api/v1/documents/verify",
        json={"document_id": str(document_id), "verifier_id": str(uploader_id)},
    )
    assert verify_resp.status_code == 200, verify_resp.text
    assert verify_resp.json()["status"] == "verified"

    # 3. Mock the list response
    mock_document_service.list_documents = AsyncMock(return_value=[verified_document_mock])
    list_resp = await async_client.get(f"/api/v1/documents/{entity_id}", params={"entity_type": "issuer"})
    assert list_resp.status_code == 200
    listed_ids = [doc["id"] for doc in list_resp.json()["documents"]]
    assert str(document_id) in listed_ids

    # 4. Mock the download response
    mock_document_service.generate_download_url = AsyncMock(
        return_value=(
            SimpleNamespace(id=document_id),
            "https://example.com/presigned-url"
        )
    )
    download_resp = await async_client.get(
        f"/api/v1/documents/{document_id}/download", params={"requestor_id": str(uploader_id)}
    )
    assert download_resp.status_code == 200
    download_payload = download_resp.json()
    assert download_payload["document_id"] == str(document_id)
    assert download_payload["download_url"].startswith("https://")

    # 5. Mock the archive response
    mock_document_service.archive_document = AsyncMock(
        return_value=SimpleNamespace(
            id=document_id,
            status="archived",
            archived_at=datetime.now(timezone.utc),
        )
    )
    delete_resp = await async_client.delete(
        f"/api/v1/documents/{document_id}", params={"archived_by": str(uploader_id)}
    )
    assert delete_resp.status_code == 200
    assert delete_resp.json()["status"] == "archived"
