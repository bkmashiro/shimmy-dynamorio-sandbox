#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-eu-west-2}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PROJECT_NAME="${PROJECT_NAME:-shimmy-dynamorio-docker-smoke}"
ROLE_NAME="${ROLE_NAME:-shimmy-codebuild-dynamorio-smoke-role}"
BUCKET="${BUCKET:-shimmy-codebuild-sources-${ACCOUNT_ID}-${REGION}}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
SOURCE_KEY="dynamorio-docker-smoke/source-${TS}.zip"
RESULT_KEY="dynamorio-docker-smoke/result-${TS}.json"
RESULT_S3_URI="s3://${BUCKET}/${RESULT_KEY}"
RESULT_PATH="${RESULT_PATH:-/tmp/dynamorio-docker-smoke-${TS}.json}"
WORK_DIR="$(mktemp -d /tmp/dynamorio-smoke-src.XXXXXX)"
cleanup() { rm -rf "$WORK_DIR" /tmp/dynamorio-smoke-source.zip; }
trap cleanup EXIT

for c in aws zip python3; do
  command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 1; }
done

rsync -a --exclude .git --exclude .cache --exclude bin --exclude /dynamorio-sandbox "$ROOT_DIR/" "$WORK_DIR/"
cp "$ROOT_DIR/codebuild-smoke/buildspec.yml" "$WORK_DIR/buildspec.yml"
( cd "$WORK_DIR" && zip -q -r /tmp/dynamorio-smoke-source.zip . )

if ! aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
  else
    aws s3api create-bucket --bucket "$BUCKET" --create-bucket-configuration "LocationConstraint=$REGION" --region "$REGION" >/dev/null
  fi
fi
aws s3 cp /tmp/dynamorio-smoke-source.zip "s3://${BUCKET}/${SOURCE_KEY}" --region "$REGION" >/dev/null

TRUST_JSON="$(mktemp /tmp/codebuild-trust.XXXXXX)"
POLICY_JSON="$(mktemp /tmp/codebuild-policy.XXXXXX)"
cat >"$TRUST_JSON" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
cat >"$POLICY_JSON" <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/codebuild/${PROJECT_NAME}*"},
 {"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::${BUCKET}","arn:aws:s3:::${BUCKET}/*"]}
]}
JSON
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "file://${TRUST_JSON}" >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "${ROLE_NAME}-policy" --policy-document "file://${POLICY_JSON}" >/dev/null
ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)"
sleep 8

PROJECT_JSON="$(mktemp /tmp/codebuild-project.XXXXXX)"
cat >"$PROJECT_JSON" <<JSON
{"name":"${PROJECT_NAME}","source":{"type":"S3","location":"${BUCKET}/${SOURCE_KEY}","buildspec":"buildspec.yml"},"artifacts":{"type":"NO_ARTIFACTS"},"environment":{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_LARGE","privilegedMode":true,"environmentVariables":[]},"serviceRole":"${ROLE_ARN}","timeoutInMinutes":90,"queuedTimeoutInMinutes":60,"logsConfig":{"cloudWatchLogs":{"status":"ENABLED","groupName":"/aws/codebuild/${PROJECT_NAME}","streamName":"build"}}}
JSON
if aws codebuild batch-get-projects --names "$PROJECT_NAME" --region "$REGION" --query 'projects[0].name' --output text 2>/dev/null | grep -qx "$PROJECT_NAME"; then
  aws codebuild update-project --cli-input-json "file://${PROJECT_JSON}" --region "$REGION" >/dev/null
else
  aws codebuild create-project --cli-input-json "file://${PROJECT_JSON}" --region "$REGION" >/dev/null
fi

BUILD_ID="$(aws codebuild start-build --project-name "$PROJECT_NAME" --region "$REGION" --environment-variables-override name=RESULT_S3_URI,value="$RESULT_S3_URI",type=PLAINTEXT --query build.id --output text)"
echo "BUILD_ID=$BUILD_ID"
LAST=""
while true; do
  BUILD_JSON="$(aws codebuild batch-get-builds --ids "$BUILD_ID" --region "$REGION")"
  STATUS="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["builds"][0]["buildStatus"])' <<<"$BUILD_JSON")"
  PHASE="$(python3 -c 'import json,sys; b=json.load(sys.stdin)["builds"][0]; print(b.get("currentPhase", ""))' <<<"$BUILD_JSON")"
  if [ "$STATUS/$PHASE" != "$LAST" ]; then echo "STATUS=$STATUS PHASE=$PHASE"; LAST="$STATUS/$PHASE"; fi
  case "$STATUS" in SUCCEEDED|FAILED|FAULT|STOPPED|TIMED_OUT) break ;; esac
  sleep 30
done
LOG_GROUP="/aws/codebuild/${PROJECT_NAME}"
LOG_STREAM="$(python3 -c 'import json,sys; b=json.load(sys.stdin)["builds"][0]; print(b.get("logs",{}).get("streamName", ""))' <<<"$BUILD_JSON")"
if [ -n "$LOG_STREAM" ]; then
  echo "--- LAST CODEBUILD LOGS ---"
  aws logs get-log-events --log-group-name "$LOG_GROUP" --log-stream-name "$LOG_STREAM" --region "$REGION" --limit 160 --query 'events[].message' --output text || true
fi
[ "$STATUS" = "SUCCEEDED" ] || { echo "CodeBuild failed: $STATUS" >&2; exit 1; }
aws s3 cp "$RESULT_S3_URI" "$RESULT_PATH" --region "$REGION" >/dev/null
echo "RESULT_PATH=$RESULT_PATH"
python3 -m json.tool "$RESULT_PATH"
