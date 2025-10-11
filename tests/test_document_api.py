from __future__ import annotations

from uuid import uuid4

import pytest


@pytest.mark.anyio("asyncio")
async def test_document_upload_verify_and_archive_flow(async_client, aws_environment):
    entity_id = uuid4()
    uploader_id = uuid4()

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
    document_id = body["id"]
    assert body["status"] == "uploaded"
    assert body["filename"] == "agreement.pdf"

    verify_resp = await async_client.post(
        "/api/v1/documents/verify",
        json={"document_id": document_id, "verifier_id": str(uploader_id)},
    )
    assert verify_resp.status_code == 200, verify_resp.text
    assert verify_resp.json()["status"] == "verified"

    list_resp = await async_client.get(f"/api/v1/documents/{entity_id}", params={"entity_type": "issuer"})
    assert list_resp.status_code == 200
    listed_ids = [doc["id"] for doc in list_resp.json()["documents"]]
    assert document_id in listed_ids

    download_resp = await async_client.get(
        f"/api/v1/documents/{document_id}/download", params={"requestor_id": str(uploader_id)}
    )
    assert download_resp.status_code == 200
    download_payload = download_resp.json()
    assert download_payload["document_id"] == document_id
    assert download_payload["download_url"].startswith("https://")

    delete_resp = await async_client.delete(
        f"/api/v1/documents/{document_id}", params={"archived_by": str(uploader_id)}
    )
    assert delete_resp.status_code == 200
    assert delete_resp.json()["status"] == "archived"
