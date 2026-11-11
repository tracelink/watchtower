#!/usr/bin/env bash
#
# Provisions the AWS resources Watchtower Phases 3/4 need: an S3 source-zip cache
# bucket, an SQS FIFO scan queue + DLQ, an IRSA IAM role, and (if missing) the
# cluster's IAM OIDC provider. See ../AWS_PROVISIONING.md for the manual, step-by-step
# version this script automates.
#
# This script NEVER touches the Kubernetes/EKS workload layer - no kubectl, no
# `eksctl` cluster-modifying commands, nothing that deploys or restarts a pod. The one
# `eksctl` call it makes (`utils associate-iam-oidc-provider`) is IAM-only bookkeeping:
# it registers an OIDC identity provider in IAM so IRSA can work, and does not touch
# any Deployment, Pod, or Service. Wiring `serviceAccountName:` into deploy.yaml and
# actually deploying remain manual, human-run steps - see the reminder this script
# prints at the end.
#
# Dev and prod are DIFFERENT AWS ACCOUNTS (confirmed 2026-09-17), matching deploy.sh's
# own profile/cluster split. Run this once per environment.
#
# Usage:
#   ./provision-aws.sh --env dev [--dry-run]
#   ./provision-aws.sh --env prod [--dry-run]
#   ./provision-aws.sh --env prod --bucket my-custom-name --yes
#   ./provision-aws.sh --env dev --aws-security-only --dry-run
#
# --dry-run prints what would happen (including a live account/resource check) without
# creating or modifying anything. Always run this first, especially for --env prod.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults per environment - matches deploy.sh's AWS_PROFILE/EKS_CLUSTER split.
# Override any of these with a flag; see --help.
# ---------------------------------------------------------------------------
ENVIRONMENT=""
AWS_REGION="us-east-1"
NAMESPACE="watchtower"           # deploy.sh's NAMESPACE is fixed; not env-specific.
SERVICE_ACCOUNT="watchtower-sa"
QUEUE_NAME="watchtower-scan-queue.fifo"
DLQ_NAME="watchtower-scan-queue-dlq.fifo"
ROLE_NAME="watchtower-scan-role"
SOURCE_TTL_DAYS=7
VISIBILITY_TIMEOUT=300
MAX_RECEIVE_COUNT=3
# Repository Scan (AWS_PROVISIONING.md section 5): its own FIFO queue, kept 14 days because a
# large scheduled run can wait a day or more; findings reports and run exports in the bucket.
REPOSCAN_QUEUE_NAME="watchtower-reposcan.fifo"
REPOSCAN_DLQ_NAME="watchtower-reposcan-dlq.fifo"
REPOSCAN_MAX_RECEIVE_COUNT=5
REPOSCAN_RETENTION_SECONDS=1209600
REPORTS_IA_DAYS=30
REPORTS_EXPIRE_DAYS=400
EXPORTS_EXPIRE_DAYS=7
DRY_RUN=false
ASSUME_YES=false
BUCKET_NAME=""      # resolved below, per-env, once ENVIRONMENT is known
AWS_PROFILE_OVERRIDE=""
EKS_CLUSTER_OVERRIDE=""
AWS_SECURITY_ONLY=false
AWS_SECURITY_SPACE_ID=""
AWS_SECURITY_SPACE_NAME=""
AWS_SECURITY_SERVICE_ROLE=""
AWS_SECURITY_WEB_APP_URL="${WATCHTOWER_AWS_SECURITY_WEB_APP_URL:-}"
AWS_SECURITY_INSTALLATION="watchtower"

usage() {
  cat <<'EOF'
Usage: scripts/provision-aws.sh --env dev|prod [--dry-run] [--yes]
  --profile NAME --region REGION --cluster NAME --bucket NAME --role NAME
  --queue NAME --dlq NAME --reposcan-queue NAME --reposcan-dlq NAME
  --namespace NAME --service-account NAME --source-ttl-days DAYS --visibility-timeout SECONDS

Security Agent setup only (skips baseline bucket, OIDC, trust and queue changes):
  --aws-security-only [--aws-security-space-name NAME | --aws-security-space-id ID]
  [--aws-security-service-role ARN] [--aws-security-installation NAME]
Discovers watchtower-<env>-agent and its service role and bucket encryption. Creates
dedicated FIFO/DLQ queues and adds scoped inline policies to existing runtime/service roles.
Saves .aws-security/<env>.json for deploy.sh. Does not deploy, activate scans, change
bucket lifecycle or role trust, or configure logs. Agent Space/code review must exist.
--dry-run performs read-only checks and prints the exact proposed resources/policy.
EOF
  exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENVIRONMENT="$2"; shift 2 ;;
    --profile) AWS_PROFILE_OVERRIDE="$2"; shift 2 ;;
    --region) AWS_REGION="$2"; shift 2 ;;
    --cluster) EKS_CLUSTER_OVERRIDE="$2"; shift 2 ;;
    --bucket) BUCKET_NAME="$2"; shift 2 ;;
    --queue) QUEUE_NAME="$2"; shift 2 ;;
    --dlq) DLQ_NAME="$2"; shift 2 ;;
    --reposcan-queue) REPOSCAN_QUEUE_NAME="$2"; shift 2 ;;
    --reposcan-dlq) REPOSCAN_DLQ_NAME="$2"; shift 2 ;;
    --role) ROLE_NAME="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --service-account) SERVICE_ACCOUNT="$2"; shift 2 ;;
    --source-ttl-days) SOURCE_TTL_DAYS="$2"; shift 2 ;;
    --visibility-timeout) VISIBILITY_TIMEOUT="$2"; shift 2 ;;
    --aws-security-only) AWS_SECURITY_ONLY=true; shift ;;
    --aws-security-space-id) AWS_SECURITY_SPACE_ID="$2"; shift 2 ;;
    --aws-security-space-name) AWS_SECURITY_SPACE_NAME="$2"; shift 2 ;;
    --aws-security-service-role) AWS_SECURITY_SERVICE_ROLE="$2"; shift 2 ;;
    --aws-security-installation) AWS_SECURITY_INSTALLATION="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
  echo "ERROR: --env dev|prod is required." >&2
  usage
fi
if [[ "$AWS_SECURITY_ONLY" == false && ( -n "$AWS_SECURITY_SPACE_ID" || -n "$AWS_SECURITY_SPACE_NAME" || -n "$AWS_SECURITY_SERVICE_ROLE" || "$AWS_SECURITY_INSTALLATION" != "watchtower" ) ]]; then
  echo "ERROR: Security Agent arguments require --aws-security-only." >&2
  exit 1
fi
if [[ -n "$AWS_SECURITY_SPACE_ID" && -n "$AWS_SECURITY_SPACE_NAME" ]]; then
  echo "ERROR: select an Agent Space by name OR ID, not both." >&2
  exit 1
fi
AWS_SECURITY_SPACE_NAME="${AWS_SECURITY_SPACE_NAME:-watchtower-${ENVIRONMENT}-agent}"

# Per-environment defaults, matching deploy.sh exactly.
if [[ "$ENVIRONMENT" == "dev" ]]; then
  AWS_PROFILE="${AWS_PROFILE_OVERRIDE:-dev-aws-profile}"
  EKS_CLUSTER="${EKS_CLUSTER_OVERRIDE:-dev-eks-cluster}"
  EXPECTED_ACCOUNT_ID="111122223333"
  # dev already owns this exact name - verified live 2026-09-17.
  BUCKET_NAME="${BUCKET_NAME:-watchtower-source-cache}"
else
  AWS_PROFILE="${AWS_PROFILE_OVERRIDE:-prod-aws-profile}"
  EKS_CLUSTER="${EKS_CLUSTER_OVERRIDE:-prod-eks-cluster}"
  EXPECTED_ACCOUNT_ID="444455556666"
  # S3 bucket names are globally unique across ALL AWS accounts, not just this one -
  # "watchtower-source-cache" is already taken by the dev account, so prod needs a
  # distinct name. SQS queue names and the IAM role name are only unique per-account,
  # so those are safe to reuse as-is across dev/prod.
  BUCKET_NAME="${BUCKET_NAME:-watchtower-source-cache-prod}"
fi

export AWS_PROFILE
export AWS_DEFAULT_REGION="$AWS_REGION"

log()  { echo "==> $*"; }
plan() { echo "    [would run] $*"; }

run() {
  if [[ "$DRY_RUN" == true ]]; then
    plan "$*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# 0. Identity check - refuses to proceed if the resolved profile points at the
#    wrong AWS account. This is the single most important safety check in this
#    script: it is what stops a --env prod run from accidentally landing in dev,
#    or vice versa, if a profile alias is ever misconfigured.
# ---------------------------------------------------------------------------
log "Checking identity for profile '$AWS_PROFILE'..."
CALLER_IDENTITY=$(aws sts get-caller-identity 2>&1) || {
  echo "ERROR: could not authenticate with profile '$AWS_PROFILE'." >&2
  echo "$CALLER_IDENTITY" >&2
  exit 1
}
ACTUAL_ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])')
if [[ "$ACTUAL_ACCOUNT_ID" != "$EXPECTED_ACCOUNT_ID" ]]; then
  echo "ERROR: profile '$AWS_PROFILE' resolved to account $ACTUAL_ACCOUNT_ID," >&2
  echo "       but --env $ENVIRONMENT expects account $EXPECTED_ACCOUNT_ID." >&2
  echo "       Refusing to proceed - this guard exists specifically to stop a" >&2
  echo "       dev/prod mixup. Pass --profile explicitly to override." >&2
  exit 1
fi
log "Confirmed: profile '$AWS_PROFILE' -> account $ACTUAL_ACCOUNT_ID (expected for --env $ENVIRONMENT)"

echo
echo "=================== PLAN ==================="
echo "Environment:       $ENVIRONMENT"
echo "AWS account:       $ACTUAL_ACCOUNT_ID"
echo "AWS profile:       $AWS_PROFILE"
echo "AWS region:        $AWS_REGION"
if [[ "$AWS_SECURITY_ONLY" == true ]]; then
  echo "Mode:              Security Agent discovery, queues and additive scoped IAM"
  echo "Agent Space:       ${AWS_SECURITY_SPACE_ID:-$AWS_SECURITY_SPACE_NAME}"
  echo "Input prefix:      s3://$BUCKET_NAME/aws-security-inputs/$AWS_SECURITY_INSTALLATION/"
  echo "IAM role:          $ROLE_NAME (existing trust preserved)"
  echo "SQS queue:         watchtower-aws-security.fifo"
  echo "SQS DLQ:           watchtower-aws-security-dlq.fifo"
else
echo "EKS cluster:       $EKS_CLUSTER"
echo "S3 bucket:         $BUCKET_NAME"
echo "SQS queue:         $QUEUE_NAME"
echo "SQS DLQ:           $DLQ_NAME"
echo "Repo scan queue:   $REPOSCAN_QUEUE_NAME (DLQ $REPOSCAN_DLQ_NAME)"
echo "IAM role:          $ROLE_NAME"
echo "K8s namespace:     $NAMESPACE"
echo "K8s ServiceAccount:$SERVICE_ACCOUNT"
echo "Source TTL (days): $SOURCE_TTL_DAYS"
fi
echo "Dry run:           $DRY_RUN"
echo "=============================================="
echo

if [[ "$DRY_RUN" == false && "$ASSUME_YES" == false ]]; then
  read -r -p "Type the account id ($ACTUAL_ACCOUNT_ID) to proceed: " CONFIRM
  if [[ "$CONFIRM" != "$ACTUAL_ACCOUNT_ID" ]]; then
    echo "Confirmation did not match. Aborting - nothing was changed." >&2
    exit 1
  fi
fi

if [[ "$AWS_SECURITY_ONLY" == true ]]; then
  SECURITY_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  SECURITY_ARGS=(--account "$ACTUAL_ACCOUNT_ID" --region "$AWS_REGION"
    --space-id "$AWS_SECURITY_SPACE_ID" --bucket "$BUCKET_NAME" --role "$ROLE_NAME"
    --space-name "$AWS_SECURITY_SPACE_NAME" --service-role "$AWS_SECURITY_SERVICE_ROLE"
    --installation "$AWS_SECURITY_INSTALLATION" --web-app-url "$AWS_SECURITY_WEB_APP_URL" --environment "$ENVIRONMENT"
    --output "$SECURITY_SCRIPT_DIR/../.aws-security/$ENVIRONMENT.json")
  [[ "$DRY_RUN" == true ]] && SECURITY_ARGS+=(--dry-run)
  python3 -B "$SECURITY_SCRIPT_DIR/provision_aws_security.py" "${SECURITY_ARGS[@]}"
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. IAM OIDC provider for the cluster (IAM-only; no cluster workload touched)
# ---------------------------------------------------------------------------
log "Checking IAM OIDC provider for $EKS_CLUSTER..."
OIDC_ISSUER=$(aws eks describe-cluster --name "$EKS_CLUSTER" --region "$AWS_REGION" \
  --query "cluster.identity.oidc.issuer" --output text)
OIDC_HOST="${OIDC_ISSUER#https://}"

if aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[].Arn" --output text \
    | tr '\t' '\n' | grep -q "oidc-provider/${OIDC_HOST}$"; then
  log "OIDC provider already registered for $EKS_CLUSTER - skipping."
else
  log "OIDC provider not found - will register it via eksctl."
  if ! command -v eksctl >/dev/null 2>&1; then
    echo "ERROR: eksctl is required to register the OIDC provider and is not on PATH." >&2
    exit 1
  fi
  run eksctl utils associate-iam-oidc-provider \
    --cluster "$EKS_CLUSTER" --region "$AWS_REGION" --approve
fi

# ---------------------------------------------------------------------------
# 2. S3 bucket
# ---------------------------------------------------------------------------
log "Checking S3 bucket $BUCKET_NAME..."
if aws s3api head-bucket --bucket "$BUCKET_NAME" >/dev/null 2>&1; then
  log "Bucket $BUCKET_NAME already exists - skipping create, still reconciling config."
else
  log "Creating bucket $BUCKET_NAME..."
  if [[ "$AWS_REGION" == "us-east-1" ]]; then
    run aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$AWS_REGION"
  else
    run aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$AWS_REGION" \
      --create-bucket-configuration LocationConstraint="$AWS_REGION"
  fi
fi

log "Reconciling bucket encryption, public access block, and lifecycle rule..."
run aws s3api put-public-access-block --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Only set encryption when the bucket has none. S3 encrypts new objects (SSE-S3) by default,
# and the organisation's SCP denies s3:PutEncryptionConfiguration (seen 2026-10-09 on dev).
if CURRENT_SSE=$(aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
    --output text 2>/dev/null) && [[ -n "$CURRENT_SSE" && "$CURRENT_SSE" != "None" ]]; then
  log "Bucket encryption already on ($CURRENT_SSE) - skipping."
else
  log "No default encryption read on $BUCKET_NAME - setting SSE-S3 (AES256)..."
  if ! run aws s3api put-bucket-encryption --bucket "$BUCKET_NAME" \
      --server-side-encryption-configuration \
      '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'; then
    log "WARNING: could not set bucket encryption (likely an SCP). New objects are still" \
        "encrypted with SSE-S3 by S3's default; continuing."
  fi
fi

run aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-source-cache",
      "Filter": {"Prefix": "source/"},
      "Status": "Enabled",
      "Expiration": {"Days": '"$SOURCE_TTL_DAYS"'}
    }, {
      "ID": "reports-retention",
      "Filter": {"Prefix": "reports/"},
      "Status": "Enabled",
      "Transitions": [{"Days": '"$REPORTS_IA_DAYS"', "StorageClass": "STANDARD_IA"}],
      "Expiration": {"Days": '"$REPORTS_EXPIRE_DAYS"'}
    }, {
      "ID": "exports-retention",
      "Filter": {"Prefix": "exports/"},
      "Status": "Enabled",
      "Expiration": {"Days": '"$EXPORTS_EXPIRE_DAYS"'}
    }, {
      "ID": "assistant-expired-transcripts",
      "Filter": {"And": {"Prefix": "assistant/conversations/", "Tags": [{"Key": "watchtower-retention", "Value": "expired"}]}},
      "Status": "Enabled",
      "Expiration": {"Days": 1},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 1}
    }, {
      "ID": "assistant-incomplete-uploads",
      "Filter": {"Prefix": "assistant/conversations/"},
      "Status": "Enabled",
      "Expiration": {"ExpiredObjectDeleteMarker": true},
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
    }]
  }'

# Watchtower marks expired transcripts daily after the last-message retention period.
# S3 lifecycle deletes only tagged versions; active conversations have no expiry tag.
# For existing buckets use assistant_retention_config.py to preserve unrelated lifecycle rules.

# ---------------------------------------------------------------------------
# 3. SQS FIFO queues, each with its DLQ: PR/upload scans, and Repository Scan
# ---------------------------------------------------------------------------
queue_url_or_planned() {
  if [[ "$DRY_RUN" == false ]]; then
    aws sqs get-queue-url --queue-name "$1" --query QueueUrl --output text
  else
    echo "https://sqs.${AWS_REGION}.amazonaws.com/${ACTUAL_ACCOUNT_ID}/$1"
  fi
}

# Creates a FIFO queue and its DLQ when missing; never changes an existing queue.
# Args: queue name, DLQ name, max receives before the DLQ, retention seconds (blank = SQS
# default). Sets ENSURED_URL and ENSURED_DLQ_URL.
ensure_fifo_queue() {
  local name="$1" dlq_name="$2" max_receive="$3" retention="$4"
  local dlq_attrs="FifoQueue=true" dlq_arn attrs
  [[ -n "$retention" ]] && dlq_attrs+=",MessageRetentionPeriod=$retention"

  log "Checking SQS DLQ $dlq_name..."
  if ENSURED_DLQ_URL=$(aws sqs get-queue-url --queue-name "$dlq_name" --query QueueUrl --output text 2>/dev/null); then
    log "DLQ $dlq_name already exists - skipping create."
  else
    log "Creating DLQ $dlq_name..."
    run aws sqs create-queue --queue-name "$dlq_name" --attributes "$dlq_attrs"
    ENSURED_DLQ_URL=$(queue_url_or_planned "$dlq_name")
  fi
  dlq_arn="arn:aws:sqs:${AWS_REGION}:${ACTUAL_ACCOUNT_ID}:${dlq_name}"

  log "Checking SQS queue $name..."
  if ENSURED_URL=$(aws sqs get-queue-url --queue-name "$name" --query QueueUrl --output text 2>/dev/null); then
    log "Queue $name already exists - skipping create."
    log "NOTE: this script does not reconcile attributes (visibility timeout, redrive" \
        "policy) on an already-existing queue, to avoid silently changing a live queue's" \
        "behavior. Use 'aws sqs set-queue-attributes' by hand if you need to change one."
    return
  fi
  attrs='{"FifoQueue": "true", "ContentBasedDeduplication": "false", "VisibilityTimeout": "'"$VISIBILITY_TIMEOUT"'"'
  [[ -n "$retention" ]] && attrs+=', "MessageRetentionPeriod": "'"$retention"'"'
  attrs+=', "RedrivePolicy": "{\"deadLetterTargetArn\":\"'"$dlq_arn"'\",\"maxReceiveCount\":\"'"$max_receive"'\"}"}'
  log "Creating queue $name (dedup off - the app supplies its own dedup id)..."
  run aws sqs create-queue --queue-name "$name" --attributes "$attrs"
  ENSURED_URL=$(queue_url_or_planned "$name")
}

ensure_fifo_queue "$QUEUE_NAME" "$DLQ_NAME" "$MAX_RECEIVE_COUNT" ""
MAIN_URL="$ENSURED_URL"
DLQ_URL="$ENSURED_DLQ_URL"

ensure_fifo_queue "$REPOSCAN_QUEUE_NAME" "$REPOSCAN_DLQ_NAME" "$REPOSCAN_MAX_RECEIVE_COUNT" \
  "$REPOSCAN_RETENTION_SECONDS"
REPOSCAN_URL="$ENSURED_URL"
REPOSCAN_DLQ_URL="$ENSURED_DLQ_URL"

# Assistant chat needs no queue: turns run on local workers coordinated through the database.
# A previously created watchtower-assistant.fifo queue/DLQ is no longer used; this script never deletes it.

# ---------------------------------------------------------------------------
# 4. IAM role - IRSA trust policy scoped to this cluster's OIDC provider + the
#    namespace/ServiceAccount pair, plus least-privilege S3/SQS permissions.
# ---------------------------------------------------------------------------
log "Checking IAM role $ROLE_NAME..."
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::${ACTUAL_ACCOUNT_ID}:oidc-provider/${OIDC_HOST}"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_HOST}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}",
        "${OIDC_HOST}:aud": "sts.amazonaws.com"
      }
    }
  }]
}
EOF
)

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "Role $ROLE_NAME already exists - skipping create, still reconciling trust + permissions policy."
  if [[ "$DRY_RUN" == false ]]; then
    echo "$TRUST_POLICY" > /tmp/watchtower-trust-policy.json
    aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
      --policy-document file:///tmp/watchtower-trust-policy.json
  else
    plan "aws iam update-assume-role-policy --role-name $ROLE_NAME --policy-document <trust policy above>"
  fi
else
  log "Creating role $ROLE_NAME..."
  if [[ "$DRY_RUN" == false ]]; then
    echo "$TRUST_POLICY" > /tmp/watchtower-trust-policy.json
    aws iam create-role --role-name "$ROLE_NAME" \
      --assume-role-policy-document file:///tmp/watchtower-trust-policy.json
  else
    plan "aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document <trust policy above>"
  fi
fi

PERMISSIONS_POLICY=$(cat <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:DeleteObjectVersion","s3:HeadObject"],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObjectTagging","s3:GetObjectVersionTagging","s3:PutObjectTagging","s3:PutObjectVersionTagging"],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/assistant/conversations/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket","s3:ListBucketVersions"],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    },
    {
      "Effect": "Allow",
      "Action": ["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage",
                 "sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],
      "Resource": ["arn:aws:sqs:${AWS_REGION}:${ACTUAL_ACCOUNT_ID}:${QUEUE_NAME}",
                   "arn:aws:sqs:${AWS_REGION}:${ACTUAL_ACCOUNT_ID}:${REPOSCAN_QUEUE_NAME}"]
	},
	{
	  "Effect": "Allow",
	  "Action": "cloudwatch:PutMetricData",
	  "Resource": "*",
	  "Condition": {"StringEquals": {"cloudwatch:namespace": "Watchtower/Runtime"}}
    }
  ]
}
EOF
)
log "Reconciling permissions policy on $ROLE_NAME..."
if [[ "$DRY_RUN" == false ]]; then
  echo "$PERMISSIONS_POLICY" > /tmp/watchtower-scan-policy.json
  aws iam put-role-policy --role-name "$ROLE_NAME" \
    --policy-name watchtower-scan-policy --policy-document file:///tmp/watchtower-scan-policy.json
  rm -f /tmp/watchtower-trust-policy.json /tmp/watchtower-scan-policy.json
else
  plan "aws iam put-role-policy --role-name $ROLE_NAME --policy-name watchtower-scan-policy --policy-document <permissions policy above>"
fi

# Runtime alarms intentionally have no actions. Notification targets can be attached later
# without changing the thresholds or granting alarm-management permissions to the pod role.
for SCAN_TYPE in pr upload; do
  run aws cloudwatch put-metric-alarm --region "$AWS_REGION" \
    --alarm-name "Watchtower-${SCAN_TYPE}-QueueDepth" \
    --namespace "Watchtower/Runtime" --metric-name "watchtower.scan.queue.depth" \
    --dimensions Name=application,Value=watchtower Name=environment,Value=production Name=type,Value="$SCAN_TYPE" \
    --statistic Maximum --period 60 --evaluation-periods 5 --datapoints-to-alarm 3 \
    --threshold 50 --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching
done

run aws cloudwatch put-metric-alarm --region "$AWS_REGION" \
  --alarm-name "Watchtower-MetricsProjectionFailures" \
  --namespace "Watchtower/Runtime" --metric-name "watchtower.metrics.projection.failures" \
  --dimensions Name=application,Value=watchtower Name=environment,Value=production \
  --statistic Sum --period 60 --evaluation-periods 1 --threshold 0 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching

run aws cloudwatch put-metric-alarm --region "$AWS_REGION" \
  --alarm-name "Watchtower-RuntimeMetricsMissing" \
  --namespace "Watchtower/Runtime" --metric-name "watchtower.runtime.heartbeat" \
  --dimensions Name=application,Value=watchtower Name=environment,Value=production \
  --statistic Minimum --period 60 --evaluation-periods 5 --datapoints-to-alarm 3 \
  --threshold 1 --comparison-operator LessThanThreshold --treat-missing-data breaching

# ---------------------------------------------------------------------------
# Summary - nothing past this point touches AWS or Kubernetes.
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" == false ]]; then
  ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)
else
  ROLE_ARN="arn:aws:iam::${ACTUAL_ACCOUNT_ID}:role/${ROLE_NAME}"
fi

echo
echo "================ SUMMARY ($ENVIRONMENT) ================"
echo "S3 bucket:    $BUCKET_NAME"
echo "SQS queue:    $MAIN_URL"
echo "SQS DLQ:      $DLQ_URL"
echo "Repo scan:    $REPOSCAN_URL"
echo "Repo scan DLQ:$REPOSCAN_DLQ_URL"
echo "IAM role ARN: $ROLE_ARN"
echo "=========================================================="
echo
echo "NOT done by this script - these remain manual, human-run steps:"
echo "  0. deploy.yaml's watchtower.reposcan.queue-url must be the 'Repo scan' url above"
echo "     for this environment. Leave watchtower.cluster.multi-pod false until you run"
echo "     more than one replica."
echo "  1. deploy.yaml already has 'serviceAccountName: $SERVICE_ACCOUNT' on the pod spec"
echo "     and watchtower.storage.s3.* / watchtower.queue.sqs.* env vars wired in (both"
echo "     confirmed done as of 2026-09-18) - nothing to add there."
echo "  2. If this run just rewrote the trust policy above (e.g. after a live drift like"
echo "     the 2026-09-18 incident, where a hand-edited policy had 'https://' left in the"
echo "     Condition keys - AssumeRoleWithWebIdentity's condition keys must be the bare"
echo "     issuer host, same as the Federated ARN, or the condition silently never"
echo "     matches and IRSA falls back to the node role), give the running pod's STS"
echo "     credential cache a few minutes to expire, or just restart the pod, to pick up"
echo "     the fix immediately."
echo "  3. Deploy via your own deploy.sh run, as always - this script never touches"
echo "     kubectl or any running workload."
