#!/usr/bin/env bash
set -euo pipefail

echo "Deploy script started."

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_ROOT}"

ENV_FILE="${ENV_FILE:-.env}"
if [[ -f "${ENV_FILE}" ]]; then
  echo "Loading environment from ${ENV_FILE}"
  # shellcheck disable=SC1090
  set -a && source "${ENV_FILE}" && set +a
fi

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
ECR_REPOSITORY="${ECR_REPOSITORY:?ECR_REPOSITORY env var required}"
ECS_CLUSTER="${ECS_CLUSTER:?ECS_CLUSTER env var required}"
ECS_SERVICE="${ECS_SERVICE:?ECS_SERVICE env var required}"
TASK_FAMILY="${TASK_FAMILY:-document-vault}"
CONTAINER_NAME="${CONTAINER_NAME:-document-vault}"
TASK_CPU="${TASK_CPU:-512}"
TASK_MEMORY="${TASK_MEMORY:-1024}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
SKIP_BUILD="${SKIP_BUILD:-false}"
EXECUTION_ROLE_ARN="${EXECUTION_ROLE_ARN:?EXECUTION_ROLE_ARN env var required}"
TASK_ROLE_ARN="${TASK_ROLE_ARN:?TASK_ROLE_ARN env var required}"
CLOUDWATCH_LOG_GROUP="${CLOUDWATCH_LOG_GROUP:-/ecs/${TASK_FAMILY}}"
CLOUDWATCH_STREAM_PREFIX="${CLOUDWATCH_STREAM_PREFIX:-ecs}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DATABASE_URL="${DATABASE_URL:?DATABASE_URL env var required}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
EPR_MOCK_MODE="${EPR_MOCK_MODE:-true}"
ECS_LAUNCH_TYPE="${ECS_LAUNCH_TYPE:-FARGATE}"
ECS_PLATFORM_VERSION="${ECS_PLATFORM_VERSION:-LATEST}"
DESIRED_COUNT="${DESIRED_COUNT:-1}"
ECS_ASSIGN_PUBLIC_IP="${ECS_ASSIGN_PUBLIC_IP:-ENABLED}"
SUBNET_ID="${SUBNET_ID:-}"
SECURITY_GROUP_ID="${SECURITY_GROUP_ID:-}"
DEFAULT_SKIP_TESTS="${DEFAULT_SKIP_TESTS:-true}"
ENABLE_DOCUMENT_CONSUMER="${ENABLE_DOCUMENT_CONSUMER:-true}"
DOCUMENT_VAULT_SQS_URL="${DOCUMENT_VAULT_SQS_URL:-}"
DOCUMENT_CONSUMER_MAX_MESSAGES="${DOCUMENT_CONSUMER_MAX_MESSAGES:-5}"
DOCUMENT_CONSUMER_WAIT_TIME="${DOCUMENT_CONSUMER_WAIT_TIME:-20}"

if [[ "${EPR_MOCK_MODE}" == "false" && -z "${EPR_SERVICE_URL}" ]]; then
  echo "ERROR: EPR_SERVICE_URL is required when EPR_MOCK_MODE is false." >&2
  exit 1
fi

if [[ -z "${AWS_ACCOUNT_ID}" ]]; then
  echo "Deriving AWS account ID via STS"
  AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
fi

ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

export AWS_REGION
export AWS_DEFAULT_REGION="${AWS_REGION}"
export AWS_ACCOUNT_ID ECR_REPOSITORY IMAGE_TAG

if [[ "${SKIP_BUILD}" != "true" ]]; then
  echo "Invoking build script for image ${IMAGE_URI}"
  SKIP_TESTS_VALUE="${SKIP_TESTS:-${DEFAULT_SKIP_TESTS}}"
  IMAGE_TAG="${IMAGE_TAG}" \
    ECR_REPOSITORY="${ECR_REPOSITORY}" AWS_REGION="${AWS_REGION}" AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID}" \
    SKIP_TESTS="${SKIP_TESTS_VALUE}" \
    ./build.sh
else
  echo "SKIP_BUILD=true; assuming image ${IMAGE_URI} already exists"
fi

TEMPLATE_PATH="${PROJECT_ROOT}/infra/ecs-task-def.json.template"
if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "ERROR: Task definition template not found at ${TEMPLATE_PATH}" >&2
  exit 1
fi

RENDERED_TASK_DEF="$(mktemp "${TMPDIR:-/tmp}/ecs-task-def.XXXXXX")"
cleanup() {
  rm -f "${RENDERED_TASK_DEF}"
}
trap cleanup EXIT

# Use sed for simple replacement
sed \
  -e "s|<TASK_FAMILY>|${TASK_FAMILY}|g" \
  -e "s|<CONTAINER_NAME>|${CONTAINER_NAME}|g" \
  -e "s|<IMAGE_URI>|${IMAGE_URI}|g" \
  -e "s|<EXECUTION_ROLE_ARN>|${EXECUTION_ROLE_ARN}|g" \
  -e "s|<TASK_ROLE_ARN>|${TASK_ROLE_ARN}|g" \
  -e "s|<TASK_CPU>|${TASK_CPU}|g" \
  -e "s|<TASK_MEMORY>|${TASK_MEMORY}|g" \
  -e "s|<ENVIRONMENT>|${ENVIRONMENT}|g" \
  -e "s|<DATABASE_URL>|${DATABASE_URL}|g" \
  -e "s|<AWS_REGION>|${AWS_REGION}|g" \
  -e "s|<DOCUMENT_VAULT_BUCKET>|${DOCUMENT_VAULT_BUCKET:?DOCUMENT_VAULT_BUCKET required}|g" \
  -e "s|<AWS_S3_KMS_KEY_ID>|${AWS_S3_KMS_KEY_ID:?AWS_S3_KMS_KEY_ID required}|g" \
  -e "s|<DOCUMENT_EVENTS_QUEUE_URL>|${DOCUMENT_EVENTS_QUEUE_URL:?DOCUMENT_EVENTS_QUEUE_URL required}|g" \
  -e "s|<AUDIT_SNS_TOPIC_ARN>|${AUDIT_SNS_TOPIC_ARN:?AUDIT_SNS_TOPIC_ARN required}|g" \
  -e "s|<PRESIGNED_URL_EXPIRATION_SECONDS>|${PRESIGNED_URL_EXPIRATION_SECONDS:-3600}|g" \
  -e "s|<LOG_LEVEL>|${LOG_LEVEL}|g" \
  -e "s|<EPR_SERVICE_URL>|${EPR_SERVICE_URL:-}|g" \
  -e "s|<EPR_MOCK_MODE>|${EPR_MOCK_MODE}|g" \
  -e "s|<ENABLE_DOCUMENT_CONSUMER>|${ENABLE_DOCUMENT_CONSUMER}|g" \
  -e "s|<DOCUMENT_VAULT_SQS_URL>|${DOCUMENT_VAULT_SQS_URL}|g" \
  -e "s|<DOCUMENT_CONSUMER_MAX_MESSAGES>|${DOCUMENT_CONSUMER_MAX_MESSAGES}|g" \
  -e "s|<DOCUMENT_CONSUMER_WAIT_TIME>|${DOCUMENT_CONSUMER_WAIT_TIME}|g" \
  -e "s|<CLOUDWATCH_LOG_GROUP>|${CLOUDWATCH_LOG_GROUP}|g" \
  -e "s|<CLOUDWATCH_STREAM_PREFIX>|${CLOUDWATCH_STREAM_PREFIX}|g" \
  "${TEMPLATE_PATH}" > "${RENDERED_TASK_DEF}"


TASK_DEF_ARN=$(aws ecs register-task-definition --cli-input-json "file://${RENDERED_TASK_DEF}" --query 'taskDefinition.taskDefinitionArn' --output text)
echo "Registered task definition: ${TASK_DEF_ARN}"

SERVICE_STATUS=$(aws ecs describe-services --cluster "${ECS_CLUSTER}" --services "${ECS_SERVICE}" --query 'services[0].status' --output text 2>/dev/null | tr -d '\r\n' || echo "NOT_FOUND")

if [[ "${SERVICE_STATUS}" == "ACTIVE" ]]; then
  echo "Updating existing ECS service ${ECS_SERVICE}"
  aws ecs update-service \
    --cluster "${ECS_CLUSTER}" \
    --service "${ECS_SERVICE}" \
    --task-definition "${TASK_DEF_ARN}" \
    --desired-count "${DESIRED_COUNT}" \
    --force-new-deployment \
    --output text >/dev/null
else
  echo "Creating ECS service ${ECS_SERVICE}"
  if [[ -z "${SUBNET_ID}" || -z "${SECURITY_GROUP_ID}" ]]; then
    echo "ERROR: SUBNET_ID and SECURITY_GROUP_ID are required to create a new service." >&2
    exit 1
  fi

  subnets_formatted=$(echo "$SUBNET_ID" | awk -F, '{for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i<NF?",":"")}')
  sgs_formatted=$(echo "$SECURITY_GROUP_ID" | awk -F, '{for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i<NF?",":"")}')
  NETWORK_CONFIGURATION="awsvpcConfiguration={subnets=[${subnets_formatted}],securityGroups=[${sgs_formatted}],assignPublicIp=${ECS_ASSIGN_PUBLIC_IP}}"

  ARGS=(
    --cluster "${ECS_CLUSTER}"
    --service-name "${ECS_SERVICE}"
    --task-definition "${TASK_DEF_ARN}"
    --desired-count "${DESIRED_COUNT}"
    --launch-type "${ECS_LAUNCH_TYPE}"
    --platform-version "${ECS_PLATFORM_VERSION}"
    --network-configuration "${NETWORK_CONFIGURATION}"
  )

  if [[ "${ECS_ENABLE_EXECUTE_COMMAND:-false}" == "true" ]]; then
    ARGS+=(--enable-execute-command)
  fi
  aws ecs create-service "${ARGS[@]}" >/dev/null
  echo "Service ${ECS_SERVICE} created."
fi

echo "Deployment complete. Track rollout in ECS console."
