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

TASK_DEFINITION_FAMILY=${TASK_DEFINITION_FAMILY:-document-vault-service}
LOG_GROUP_NAME=${LOG_GROUP_NAME:-/ecs/document-vault}

rendered_task_def=$(mktemp)
trap 'rm -f "$rendered_task_def"' EXIT

sed \
  -e "s|<ECS_EXECUTION_ROLE_ARN>|${ECS_EXECUTION_ROLE_ARN:?ECS_EXECUTION_ROLE_ARN required}|g" \
  -e "s|<ECS_TASK_ROLE_ARN>|${ECS_TASK_ROLE_ARN:?ECS_TASK_ROLE_ARN required}|g" \
  -e "s|<IMAGE_URI>|${IMAGE_URI}|g" \
  -e "s|<ENVIRONMENT>|${ENVIRONMENT:-prod}|g" \
  -e "s|<DATABASE_URL>|${DATABASE_URL:?DATABASE_URL required}|g" \
  -e "s|<DATABASE_POOL_SIZE>|${DATABASE_POOL_SIZE:-5}|g" \
  -e "s|<DATABASE_MAX_OVERFLOW>|${DATABASE_MAX_OVERFLOW:-10}|g" \
  -e "s|<AWS_REGION>|${AWS_DEFAULT_REGION}|g" \
  -e "s|<DOCUMENT_VAULT_BUCKET>|${DOCUMENT_VAULT_BUCKET:?DOCUMENT_VAULT_BUCKET required}|g" \
  -e "s|<AWS_S3_KMS_KEY_ID>|${AWS_S3_KMS_KEY_ID:?AWS_S3_KMS_KEY_ID required}|g" \
  -e "s|<DOCUMENT_EVENTS_QUEUE_URL>|${DOCUMENT_EVENTS_QUEUE_URL:?DOCUMENT_EVENTS_QUEUE_URL required}|g" \
  -e "s|<PRESIGNED_URL_EXPIRATION_SECONDS>|${PRESIGNED_URL_EXPIRATION_SECONDS:-900}|g" \
  -e "s|<LOG_LEVEL>|${LOG_LEVEL:-INFO}|g" \
  -e "s|<LOG_FORMAT>|${LOG_FORMAT:-json}|g" \
  -e "s|<ACCESS_CONTROL_ALLOW_ALL>|${ACCESS_CONTROL_ALLOW_ALL:-false}|g" \
  -e "s|<BLOCKCHAIN_ENDPOINT_URL>|${BLOCKCHAIN_ENDPOINT_URL:-}|g" \
  -e "s|<LOG_GROUP_NAME>|${LOG_GROUP_NAME}|g" \
  -e "s|<JWT_PUBLIC_KEY_SSM_ARN>|${JWT_PUBLIC_KEY_SSM_ARN:-}|g" \
  infra/ecs-task-def.json > "$rendered_task_def"

aws ecs register-task-definition --family "$TASK_DEFINITION_FAMILY" --cli-input-json file://"$rendered_task_def"

echo "Task definition registered: $TASK_DEFINITION_FAMILY"

declare -a REQUIRED_VALUES=(CLUSTER SUBNET_ID SECURITY_GROUP_ID)
for var in "${REQUIRED_VALUES[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: $var env required" >&2
    exit 1
  fi
done

NETWORK_CONFIGURATION="awsvpcConfiguration={subnets=[\"$SUBNET_ID\"],securityGroups=[\"$SECURITY_GROUP_ID\"],assignPublicIp=\"ENABLED\"}"

RESULT=$(aws ecs run-task \
  --cluster "$CLUSTER" \
  --launch-type FARGATE \
  --task-definition "$TASK_DEFINITION_FAMILY" \
  --platform-version LATEST \
  --network-configuration "$NETWORK_CONFIGURATION" \
  --query 'tasks[0].taskArn' --output text)

echo "Started task: $RESULT"
