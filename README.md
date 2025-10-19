# Document Vault Service

## Overview
Document Vault is the secure storage and verification layer for legal and compliance documents that back tokenized assets.  
The service provides:

- Authenticated APIs for uploading, verifying, listing, downloading, and archiving documents.
- Strong hashing (SHA-256) with mock blockchain registration for tamper detection.
- Encrypted document storage in AWS S3 (SSE-KMS) and signed URL distribution.
- Event emission (`document.uploaded`, `document.verified`, `document.mismatch`, `document.archived`) over SQS for downstream systems.
- Compliance-ready audit trails persisted in Postgres (Supabase).
- Cloud-native deployment targeting AWS Fargate (ECS) with Docker packaging.

> Access control is currently mocked to always authorize requests. Replace `AccessControlService` when the dedicated microservice is available.

---

## Architecture Summary

| Concern             | Implementation                                                                                                                                                                                         |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Framework           | FastAPI + Pydantic v2                                                                                                                                                                                  |
| Infrastructure      | AWS S3 (encrypted), AWS SQS, Supabase Postgres, CloudWatch Logs → Kinesis Firehose → S3 for audit retention, AWS ECS (Fargate)                                                                          |
| Core modules        | `DocumentService` orchestrates hashing, storage, audit logging, event publishing, and blockchain integration (mocked).                                                                                   |
| Data integrity      | SHA-256 hashing, on-chain registration (mock), periodic rehashing support, and append-only `audit_logs`.                                                                                                |
| Security            | TLS enforced via AWS endpoints, S3 SSE-KMS, signed download URLs, future JWT verification hook, infrastructure secrets via `.env` or AWS Secrets Manager / SSM Parameter Store.                          |
| Observability       | Structured JSON logging (structlog) → CloudWatch Logs, recommended Kinesis Firehose sink to encrypted S3 for immutable archival and analytics.                                                          |

---

## Repository Layout

```
app/
  api/                # FastAPI routers and dependency wiring
  core/               # Settings and logging configuration
  db/                 # Async SQLAlchemy session management
  events/             # AWS SQS publisher
  models/             # SQLAlchemy models and custom types
  schemas/            # Pydantic schemas for request/response
  services/           # Domain services (storage, hashing, audit, blockchain mock)
infra/ecs-task-def.json
tests/                # Pytest suite using moto for AWS mocks
build.sh / deploy.sh  # CI/CD helpers
Dockerfile / .dockerignore
.env.example          # Required configuration placeholders
.venv/                # Local virtualenv (created via `python3 -m venv .venv`)
```

---

## Environment Configuration

1. Duplicate `.env.example` to `.env` (or `.env.prod` for deployment) and populate the values.
2. Secrets such as JWT keys and Supabase credentials should live in AWS Secrets Manager / SSM parameters.  
   The ECS task definition template expects `JWT_PUBLIC_KEY` to come from SSM.
3. Required variables (non-exhaustive):

| Variable                         | Description                                                                                         |
|----------------------------------|-----------------------------------------------------------------------------------------------------|
| `DATABASE_URL`                   | Supabase connection string (`postgresql+psycopg://...`). Use the **Transaction pooling** connection string with port `6543`. |
| `DATABASE_POOL_PRE_PING`         | Toggle connection pre-ping; set `false` for async SQLite or local tests.                           |
| `DOCUMENT_VAULT_BUCKET`          | Private S3 bucket for document binaries (versioning & default encryption enabled).                 |
| `AWS_S3_KMS_KEY_ID`              | Customer-managed CMK ARN applied to S3 uploads.                                                    |
| `DOCUMENT_EVENTS_QUEUE_URL`      | SQS queue URL for document events; configure DLQ & retention policies externally.                 |
| `PRESIGNED_URL_EXPIRATION_SECONDS` | Signed URL TTL (recommended < 3600s).                                                               |
| `LOG_GROUP_NAME`                 | CloudWatch Logs group for ECS task logging.                                                        |
| `ECS_EXECUTION_ROLE_ARN`         | Role granting ECS task permissions (ECR pull, CloudWatch logs).                                    |
| `ECS_TASK_ROLE_ARN`              | Role granting runtime access to S3, SQS, KMS, Secrets Manager, etc.                                |

---

## Local Development

### Prerequisites

- Python 3.11 or 3.12 (Python 3.13 is not yet supported by `pydantic-core` / `psycopg`)
- Docker Engine + BuildKit (`docker buildx`)
- AWS CLI v2
- Optional: `direnv` for automatic environment variable loading

### Bootstrap

```bash
# 1. Create a virtual environment (already provisioned as `.venv` in this repo)
python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Set local environment variables
cp .env.example .env
# Edit .env as needed (local Supabase URL, LocalStack S3/SQS endpoints, etc.)

# 4. Ensure the database schema exists (see next section)
# Apply the SQL snippet against your local database if the core service hasn't provisioned it yet.

# 5. Start the API
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

> Use Python 3.11 or 3.12 only. Python 3.13 is currently unsupported by upstream dependencies (`pydantic-core`, `psycopg`).

Navigate to `http://localhost:8000/docs` for interactive Swagger documentation.

---

## Database & Migrations

Schema migrations are managed centrally by the platform's core service, so this repository no longer includes Alembic configuration or migration scripts. For local development, ensure the upstream migrations have been applied or recreate the minimal schema using the snippet below.

### Manual Schema Setup

Run the following SQL in your Supabase SQL editor (or any PostgreSQL client) if you need to bootstrap a fresh database yourself.

```sql
-- Optional enums for stricter validation
CREATE TYPE "documententitytype" AS ENUM ('issuer', 'investor', 'deal', 'token', 'compliance');
CREATE TYPE "documenttype" AS ENUM ('operating_agreement', 'offering_memorandum', 'subscription', 'kyc', 'audit_report', 'other');
CREATE TYPE "documentstatus" AS ENUM ('uploaded', 'verified', 'mismatch', 'archived');

-- Documents
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    entity_type VARCHAR(32) NOT NULL,
    entity_id UUID NOT NULL,
    token_id INTEGER,
    document_type VARCHAR(32) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(255) NOT NULL,
    size_bytes INTEGER NOT NULL,
    storage_bucket VARCHAR(63) NOT NULL,
    storage_key VARCHAR(512) NOT NULL UNIQUE,
    storage_version_id VARCHAR(255),
    sha256_hash VARCHAR(128) NOT NULL,
    hash_verified_at TIMESTAMPTZ,
    status VARCHAR(16) NOT NULL,
    on_chain_reference VARCHAR(255),
    uploaded_by UUID NOT NULL,
    verified_by UUID,
    archived_by UUID,
    archived_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS ix_documents_sha256_hash ON documents (sha256_hash);

-- Shared audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id UUID,
    actor_type VARCHAR(64) NOT NULL DEFAULT 'user',
    entity_id UUID,
    entity_type VARCHAR(64),
    action VARCHAR(120) NOT NULL,
    correlation_id VARCHAR(120),
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_actor ON audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_entity ON audit_logs (entity_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
```

> **Note**: SQLAlchemy stores enum values as `VARCHAR` columns (`native_enum=False`). If you provisioned earlier versions of the schema with native PostgreSQL `ENUM` types, adjust them to match the definitions above.

---

## Testing

```bash
source .venv/bin/activate
pytest
```

- Tests leverage `moto` to emulate S3 and SQS interactions, and SQLite (async) for the database.
- `build.sh` always executes the test suite before building & pushing the Docker image.
- If running in a restricted network, ensure you have access to Python package indices or mirror wheels locally.

---

## Build & Deployment Workflow

1. **Build (`build.sh`)**
   - Creates/uses `.venv`, installs dependencies, and runs `pytest`.
   - Authenticates to ECR, ensures the repository exists, and builds/pushes a multi-arch image using `docker buildx`.
   - Inputs: `.env.prod` (or override via `ENV_FILE`), AWS credentials with ECR permissions.

2. **Deploy (`deploy.sh`)**
   - Renders `infra/ecs-task-def.json` into a concrete task definition by interpolating environment values.
   - Registers the task definition and starts a one-off Fargate task (customize to update an ECS service if preferred).
   - Requires `CLUSTER`, `SUBNET_ID`, `SECURITY_GROUP_ID`, task/exec role ARNs, and networking primitives.

3. **ECS Task Definition**
   - Container listens on port 8000, uses `uvicorn`, health check at `/healthz`.
   - Logs ship to CloudWatch (`<LOG_GROUP_NAME>`). Configure Kinesis Firehose to continuously export to an encrypted, versioned S3 bucket for immutable audit retention.

---

## Runtime Behaviour

### API Surface (`/api/v1`)

| Method | Route                             | Description                                                                                           |
|--------|-----------------------------------|-------------------------------------------------------------------------------------------------------|
| POST   | `/documents/upload`               | Multipart upload (`file`, metadata form fields). Stores binary in S3, records metadata + audit log.  |
| POST   | `/documents/verify`               | Re-hashes object retrieved from S3, updates status (`verified` / `mismatch`), emits SQS event.       |
| GET    | `/documents/{entity_id}`          | Lists documents for an issuer/investor/deal (`entity_type` query param).                             |
| GET    | `/documents/{id}/download`        | Returns a short-lived presigned URL (requires `requestor_id`).                                       |
| DELETE | `/documents/{id}`                 | Soft-archives document (status → `archived`), logs event, emits SQS notification.                    |

All responses are Pydantic models defined in `app/schemas/document.py`.

### Event Contracts

- `document.uploaded`, `document.verified`, `document.mismatch`, `document.archived`.
- Message body JSON:

```json
{
  "event_type": "document.verified",
  "occurred_at": "2024-06-01T12:34:56.789Z",
  "payload": {
    "document_id": "uuid",
    "entity_type": "issuer",
    "entity_id": "uuid",
    "sha256_hash": "..."
  }
}
```

Extend payloads as downstream consumers evolve; maintain backwards compatibility via versioned contracts if needed.

---

## Security & Compliance Notes

- **Encryption in transit**: enforced via HTTPS endpoints for S3/SQS and TLS termination at load balancer or API gateway.
- **Encryption at rest**: S3 uploads enforce `ServerSideEncryption=aws:kms` with `AWS_S3_KMS_KEY_ID`; enable bucket versioning and MFA delete.
- **Audit logging**: Application logs → CloudWatch Logs → Kinesis Firehose → encrypted S3 (immutable). Database `audit_logs` provide structured audit events with user attribution.
- **Access control**: Currently mocked (returns `True`). Replace `AccessControlService` with real microservice integration before production launch.
- **Secrets management**: Prefer AWS Secrets Manager/SSM for database credentials, JWT keys, and blockchain endpoints. Reference them in ECS task definition via `secrets`.
- **Networking**: Deploy ECS tasks in private subnets with VPC endpoints for S3/SQS/KMS. Enable security group egress restrictions.

---

## Extensibility Roadmap

- Integrate real blockchain gateway and persist transaction receipts.
- Replace RBAC mock with the dedicated Access Control service.
- Support document versioning and lifecycle policies (retention, legal hold).
- Add scheduled rehash jobs (AWS EventBridge + Lambda) to detect drift against on-chain hashes.
- Implement dead-letter queues and retries for SQS publishing.
- Expose admin endpoints for audit exports and per-entity analytics.
- Extend to support DocuSign / HelloSign callbacks for auto ingestion.

---

## Troubleshooting

- **Dependencies fail to install offline**: mirror Python packages locally or configure a private PyPI proxy; scripts assume outbound network access.
- **`pytest` cannot locate AWS services**: ensure environment variables align with moto defaults (`AWS_REGION`, `DOCUMENT_VAULT_BUCKET`).
- **ECS task IAM errors**: confirm task role grants `s3:PutObject`, `s3:GetObject`, `kms:Encrypt/Decrypt`, `sqs:SendMessage`, and read access to Secrets Manager parameters.

---

## Support

For questions or clarifications, contact the platform team or update this README with additional runbooks as the ecosystem evolves.
