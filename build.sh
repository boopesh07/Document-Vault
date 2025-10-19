#!/usr/bin/env bash
set -euo pipefail

echo "Build script started."

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_ROOT}"

ENV_FILE="${ENV_FILE:-.env}"
if [[ -f "${ENV_FILE}" ]]; then
  echo "Loading environment from ${ENV_FILE}"
  # shellcheck disable=SC1090
  set -a && source "${ENV_FILE}" && set +a
fi

PYTHON=${PYTHON:-.venv/bin/python}
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
ECR_REPOSITORY="${ECR_REPOSITORY:?ECR_REPOSITORY env var required}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
SKIP_TESTS="${SKIP_TESTS:-false}"
BUILD_PLATFORM="${BUILD_PLATFORM:-linux/amd64}"

if [[ -z "${AWS_ACCOUNT_ID}" ]]; then
  echo "Deriving AWS account ID via STS"
  AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
fi

ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

if [[ "${SKIP_TESTS}" != "true" ]]; then
  if [[ -x "${PYTHON}" ]]; then
    echo "Running test suite with ${PYTHON}"
    "${PYTHON}" -m pytest -vv
  else
    echo "WARNING: ${PYTHON} not found; skipping tests" >&2
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Please install and start Docker." >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: aws CLI not found. Please install awscli v2." >&2
  exit 1
fi

echo "Logging into ECR registry ${ECR_REGISTRY}"
aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}"

echo "Ensuring ECR repository ${ECR_REPOSITORY} exists"
aws ecr describe-repositories --repository-names "${ECR_REPOSITORY}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPOSITORY}" >/dev/null

if docker buildx version >/dev/null 2>&1; then
  BUILDER_NAME="${BUILDER_NAME:-document-vault-builder}"
  if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    echo "Creating docker buildx builder ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use >/dev/null
  else
    docker buildx use "${BUILDER_NAME}" >/dev/null
  fi

  if [[ "${CLEAN_BUILDX:-false}" == "true" ]]; then
    docker buildx prune -af >/dev/null || true
  fi

  echo "Building and pushing multi-platform image ${IMAGE_URI}"
  docker buildx build \
    --builder "${BUILDER_NAME}" \
    --platform "${BUILD_PLATFORM}" \
    -t "${IMAGE_URI}" \
    --push \
    .
else
  echo "docker buildx not available; falling back to docker build"
  docker build -t "${IMAGE_URI}" -f Dockerfile .
  docker push "${IMAGE_URI}"
fi

echo "Build and push complete: ${IMAGE_URI}"
