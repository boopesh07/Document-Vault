#  vaults-and-registries / document-vault-microservice

Welcome to the **Document Vault** — the secure storage and verification layer for legal and compliance documents that back Omen's tokenized assets.

This service is the source of legal truth, ensuring every document is securely stored, verifiable, and accessible only to authorized users. It forms a foundational pillar of Omen's compliance and security architecture.

---

## Quick Start Workflows

### 1) Upload & Verify a Document
1.  **Upload** a document with its associated entity metadata (`entity_id`, `document_type`, etc.) via the `/upload` API.
2.  The Vault stores the file securely in **AWS S3**, computes its **SHA-256 hash**, and records the transaction in the database and audit log.
3.  **Verify** the document's integrity at any time via the `/verify` API, which re-hashes the stored file and compares it against the original hash.

**Docs:**
*   [API Overview](#api-overview)
*   [Core Concepts / Hashing & Verification](#hashing--verification)

### 2) Securely Download a Document
1.  Request a secure, short-lived download link for a specific document using the `/download` API.
2.  The service checks the requestor's permissions against the **Entity & Permissions Core (EPR)**.
3.  If authorized, the service generates and returns a **presigned S3 URL** with a limited expiration time.

**Docs:**
*   [API Overview](#api-overview)
*   [Core Concepts / Secure Storage](#secure-storage)

### 3) Archive a Document
1.  Perform a "soft delete" of a document by calling the `DELETE` endpoint.
2.  The document's status is changed to `archived`, preserving the record for audit and compliance purposes.
3.  An `document.archived` event is emitted for downstream systems.

---

## Core Concepts

### Documents & Legal Truth
The service treats every file as a representation of legal or compliance truth. Documents are linked to core system entities (Issuers, Investors, Deals, etc.) and form the basis of trust and auditability on the platform.

### Hashing & Verification
To ensure data integrity, every uploaded document is hashed using **SHA-256**. This hash is stored in the database and serves as a unique fingerprint. The `/verify` endpoint provides a mechanism to detect tampering by re-calculating the hash and comparing it to the original. A mock **Blockchain Gateway** integration is included to represent future on-chain registration of these hashes.

### Secure Storage
Documents are stored in a private **AWS S3** bucket. All files are encrypted at rest using **server-side encryption with AWS KMS (SSE-KMS)**. Direct access to the S3 bucket is disallowed; all downloads are served through temporary, secure **presigned URLs**.

### Audit Trail
Every significant action (upload, verification, archival) publishes an audit event to a centralized SNS topic (`arn:aws:sns:us-east-1:116981763412:epr-audit-events`). The EPR (Entity & Permissions) service consumes these events and persists them in a centralized audit database. This creates an immutable, compliance-ready audit trail that tracks who did what, and when.

### Event-Driven Architecture
The Document Vault is a decoupled service that communicates state changes through an event-driven model. It publishes events like `document.uploaded`, `document.verified`, and `document.archived` to an **AWS SQS** queue, allowing other microservices to react to document lifecycle events in real-time.

---

## Data Model (at a glance)

-   **`documents`** — The core table for document metadata.
    -   `id` (UUID), `entity_id` (UUID), `entity_type` (varchar), `document_type` (varchar), `filename` (varchar), `storage_bucket` (varchar), `storage_key` (varchar), `sha256_hash` (varchar), `status` (varchar), `uploaded_by` (UUID), `verified_by` (UUID), `archived_by` (UUID), `created_at` (timestamptz).

> **Note**: Audit logs are managed centrally by the EPR service. This service publishes audit events to SNS (`arn:aws:sns:us-east-1:116981763412:epr-audit-events`).

---

## API Overview

The full interactive OpenAPI/Swagger documentation is available at `/docs` on the running service.

-   **`POST /api/v1/documents/upload`**
    -   Uploads a new document. Expects multipart form data with a `file` and metadata fields (`entity_id`, `document_type`, etc.).
-   **`POST /api/v1/documents/verify`**
    -   Initiates a verification check for an existing document.
-   **`GET /api/v1/documents/{entity_id}`**
    -   Lists all documents associated with a specific entity ID and type.
-   **`GET /api/v1/documents/{document_id}/download`**
    -   Generates and returns a secure, short-lived presigned URL for downloading a document.
-   **`DELETE /api/v1/documents/{document_id}`**
    -   Archives a document, marking it as inactive.

---

## System Interactions & Integrations

-   **Entity & Permissions Core (EPR)**
    -   The Document Vault **does not** manage permissions itself. For every action that requires authorization (e.g., upload, download), it makes a call to the EPR service to determine if the requesting user has the required permissions for the given resource.
    -   Currently, this is simulated via `EprServiceMock`.
-   **Blockchain Gateway**
    -   Upon successful verification, the service sends the document's hash to a Blockchain Gateway for on-chain registration. This provides a public, immutable timestamp of the document's state.
    -   This is currently a mocked service.
-   **Downstream Consumers (via SQS)**
    -   Any service that needs to react to document changes (e.g., a compliance engine, a notification service) can subscribe to the `document-events` SQS queue.

---

## Security & Compliance (high level)

-   **Encryption in Transit:** All API and AWS endpoints are protected with TLS/HTTPS.
-   **Encryption at Rest:** All documents in S3 are encrypted using AWS KMS keys.
-   **Access Control:** All operations are gated by authorization checks against the EPR.
-   **Auditability:** Every action creates a persistent, structured audit log. Logs are also shipped to CloudWatch for retention and analysis.
-   **Secrets Management:** Sensitive credentials (database URLs, AWS keys) are managed via environment variables, intended to be populated by a secrets manager like AWS Secrets Manager or SSM Parameter Store in production.

---

## Roadmap (high level)

-   **Integrate Real EPR Service:** Replace the `EprServiceMock` with a live client for the Entity & Permissions Core.
-   **Integrate Real Blockchain Gateway:** Connect to a production blockchain service and persist real transaction receipts.
-   **Support Document Versioning:** Introduce the ability to upload and manage multiple versions of a single document.
-   **Scheduled Rehash Jobs:** Implement a recurring job (e.g., AWS EventBridge + Lambda) to periodically re-verify all documents and detect potential data drift or corruption.
-   **Dead-Letter Queues (DLQs):** Add DLQ configurations for the SQS event publishing to handle message failures gracefully.

---

*Last updated: 2025-10-15*



