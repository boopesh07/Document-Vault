# Document Vault Overview

Document Vault is Omen’s legal-truth service: it ingests, stores, and verifies artefacts that back tokenized assets while enforcing access permissions through the Entity & Permissions (EPR) platform.

## What It Does

- **Document lifecycle** – upload, list, relink, verify, and archive documents; metadata lives in Postgres.
- **Secure storage** – binaries reside in an S3 bucket with SSE‑KMS; presigned URLs gate distribution.
- **Integrity guarantees** – SHA‑256 hashing prevents tampering, and integrity alerts fire on mismatch.
- **Event emission** – lifecycle events hit SQS, audit events are sent to the EPR service's API, and compliance alerts hit their own queue.
- **Entity clean-up** – an SQS-backed consumer cascade-archives documents when upstream entities disappear.

---

## Quick Workflows

| Workflow | Calls & Notes |
|----------|---------------|
| **Upload** | `POST /api/v1/documents/upload`; validates MIME, size, duplicates → stores to S3 → writes metadata → publishes `document.uploaded`. |
| **Verify** | `POST /api/v1/documents/verify`; streams S3 object, re-hashes, updates status (`verified`/`mismatch`), publishes events, triggers integrity alert on mismatch. |
| **Download** | `GET /api/v1/documents/{document_id}/download`; checks EPR, returns presigned URL (≤ 1h expiry). |
| **List** | `GET /api/v1/documents/{entity_id}`; returns all non-archived documents for an entity. |
| **Relink** | `POST /api/v1/documents/{document_id}/relink`; rebinds entity/token, emits `document.relinked`. |
| **Archive** | `DELETE /api/v1/documents/{document_id}`; soft delete + lifecycle/audit events. |
| **Cascade Archive** | `DocumentVaultConsumer` processes `entity.deleted` SQS messages, archives linked docs, records processed event ids. |

---

## Architecture Snapshot

| Layer | Details |
|-------|---------|
| API | FastAPI routers under `app/api/routes`, Pydantic v2 request/response models. |
| Services | `DocumentService`, `StorageService`, `HashingService`, `AuditEventPublisher`, `DocumentEventPublisher`, `BlockchainService` (mock), `EprService` / `EprServiceMock`. |
| Persistence | Async SQLAlchemy with Postgres; models in `app/models`. |
| Storage | aioboto3 S3 client, SSE‑KMS enforced, presigned URL helper. |
| Messaging | SQS (document lifecycle + integrity alerts) and direct API calls to EPR for audit events. |
| Background | `DocumentVaultConsumer` long-polls queue configured via env vars. |

---

## Data Model Highlights

- **`documents` table** – captures entity linkage, document type, storage info, hash, status (`uploaded`, `verified`, `mismatch`, `archived`), actor stamps, optional JSON metadata.
- **`document_vault_processed_events` table** – deduplication ledger for SQS consumer (`event_id` unique + metadata).

All audit activity is sent synchronously to the EPR service's event API instead of being stored in a local table.

---

## Integrations

- **EPR** – authorizes all user actions; mock implementation grants configurable role-based access locally.
- **EPR Event API / SQS** – Audit events are sent directly to the EPR API. Lifecycle events (`document.uploaded`, etc.) and compliance alerts are published to SQS.
- **S3** – binary storage, streaming for re-hash, presigned URL generation.
- **Blockchain (mock)** – placeholder for eventual real hash anchoring.

---

## Security & Compliance

- HTTPS everywhere; SSE‑KMS for data at rest.
- Presigned URLs capped at one hour; configurable default.
- Structured logging via structlog, designed for CloudWatch ingestion.
- Secrets provided through environment variables (prefer IAM roles / Secrets Manager in production).

---

## Known Gaps

1. Listing endpoint lacks requester context; authorization should guard entity-level reads.
2. `StorageService.generate_presigned_url` awaits a sync helper; fix to prevent runtime errors.
3. Consumer dedup rollback can undo completed archival work; tighten transaction handling.

---

## Roadmap

- Wire the service to the live EPR system and remove mock defaults.
- Replace the blockchain stub with a production gateway & store receipts.
- Implement document versioning and retention policies.
- Schedule automated rehash jobs (EventBridge + Lambda).
- Add DLQs/metrics for publisher + consumer pipelines.

---

**Last updated:** November 2025

