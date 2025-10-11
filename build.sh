#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.prod}"
if [[ -f "$ENV_FILE" ]]; then
  echo "Loading environment from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
else
  echo "INFO: $ENV_FILE not found. Proceeding with current environment." >&2
fi

python_exec=${PYTHON:-python3}
"$python_exec" - <<'PY'
import sys
if sys.version_info[:2] >= (3, 13) or sys.version_info[:2] < (3, 11):
    raise SystemExit(
        "Python 3.11 or 3.12 is required for this project due to upstream dependency support (pydantic-core, psycopg)."
    )
PY
if [[ ! -d .venv ]]; then
  echo "Creating virtual environment (.venv)"
  "$python_exec" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
pytest

deactivate || true

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Please install/start Docker." >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: aws CLI not found." >&2
  exit 1
fi

export AWS_DEFAULT_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}

if [[ -z "${ACCOUNT_ID:-}" ]]; then
  if ! ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null); then
    echo "ERROR: ACCOUNT_ID not set and could not be derived via AWS STS." >&2
    exit 1
  fi
fi

ECR_REPOSITORY=${ECR_REPOSITORY:-document-vault}
IMAGE_TAG=${IMAGE_TAG:-latest}
ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"
aws ecr describe-repositories --repository-names "$ECR_REPOSITORY" >/dev/null 2>&1 || aws ecr create-repository --repository-name "$ECR_REPOSITORY" >/dev/null

docker buildx version >/dev/null 2>&1 || { echo "ERROR: docker buildx not available." >&2; exit 1; }

BUILDER="document-vault-builder"
if docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx use "$BUILDER" >/dev/null 2>&1 || true
else
  docker buildx create --name "$BUILDER" --driver docker-container --use >/dev/null 2>&1
fi

if [[ "${CLEAN_BUILDX:-}" == "true" ]]; then
  docker buildx prune -af || true
fi

docker buildx build \
  --builder "$BUILDER" \
  --platform linux/amd64 \
  -t "$IMAGE_URI" \
  --push \
  .

echo "Image pushed: $IMAGE_URI"
