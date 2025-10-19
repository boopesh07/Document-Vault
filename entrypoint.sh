#!/usr/bin/env bash
set -euo pipefail

APP_MODULE=${APP_MODULE:-"app.main:app"}
HOST=${HOST:-"0.0.0.0"}
PORT=${PORT:-"8000"}
WORKERS=${WORKERS:-"4"}

# Note: Database migrations are handled by the EPR service, not this service.
echo "Starting Document Vault service..."

exec uvicorn "${APP_MODULE}" --host "${HOST}" --port "${PORT}" --workers "${WORKERS}"
