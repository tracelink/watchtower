# AWS Provisioning for Phase 3 (S3) & Phase 4 (SQS)

Nothing in `IMPROVEMENT_PLAN.md` Phase 3 or Phase 4 can start until these exist. All of it is
outside this repository and needs whoever owns the AWS account and the EKS cluster
(`dev-eks-cluster`, account `111122223333`, region `us-east-1`, per `deploy.yaml`
and the current `kubectl` context).

Everything uses IRSA (IAM Roles for Service Accounts) — no `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` anywhere. Do these roughly in order; later steps reference earlier ones.

---

## 0. Check whether the cluster already has an IAM OIDC provider

IRSA needs exactly one of these per cluster. Many accounts already have it from other
workloads — check before creating a duplicate.

```bash
aws eks describe-cluster --name dev-eks-cluster --region us-east-1 \
  --query "cluster.identity.oidc.issuer" --output text
```

Compare that issuer URL against:

```bash
aws iam list-open-id-connect-providers
```

If it's not listed, create it:

```bash
eksctl utils associate-iam-oidc-provider \
  --cluster dev-eks-cluster --region us-east-1 --approve
```

---

## 1. S3 bucket

```bash
aws s3api create-bucket --bucket watchtower-source-cache --region us-east-1

aws s3api put-public-access-block --bucket watchtower-source-cache \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-encryption --bucket watchtower-source-cache \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-bucket-lifecycle-configuration --bucket watchtower-source-cache \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-source-cache",
      "Filter": {"Prefix": "source/"},
      "Status": "Enabled",
      "Expiration": {"Days": 7}
    }]
  }'
```

The `7` day expiration is a placeholder (the plan calls this `source-ttl-days` but doesn't pin a
number) — pick a retention window that matches how long the S3 source-zip cache should stay warm.

---

## 2. SQS FIFO queue + DLQ

Create the dead-letter queue first, then the main queue pointing at it:

```bash
aws sqs create-queue --queue-name watchtower-scan-queue-dlq.fifo --attributes FifoQueue=true

DLQ_ARN=$(aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name watchtower-scan-queue-dlq.fifo \
    --query QueueUrl --output text) \
  --attribute-names QueueArn --query Attributes.QueueArn --output text)

aws sqs create-queue --queue-name watchtower-scan-queue.fifo --attributes '{
  "FifoQueue": "true",
  "ContentBasedDeduplication": "false",
  "VisibilityTimeout": "300",
  "RedrivePolicy": "{\"deadLetterTargetArn\":\"'"$DLQ_ARN"'\",\"maxReceiveCount\":\"3\"}"
}'
```

Notes:
- `ContentBasedDeduplication: false` is deliberate — the application supplies its own
  `MessageDeduplicationId`, so content-based dedup would be redundant.
- `VisibilityTimeout` of `300` (5 min) above is a placeholder. Set it to your actual expected
  max scan duration; too short and a slow scan gets redelivered mid-processing, causing a
  duplicate.

---

## 3. IAM role + policy

Trust policy — fill in `<OIDC_ISSUER_HOST>` with the issuer URL from step 0, **without** the
`https://` prefix:

```bash
cat > trust-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/<OIDC_ISSUER_HOST>"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "<OIDC_ISSUER_HOST>:sub": "system:serviceaccount:watchtower:watchtower-sa",
        "<OIDC_ISSUER_HOST>:aud": "sts.amazonaws.com"
      }
    }
  }]
}
EOF

aws iam create-role --role-name watchtower-scan-role \
  --assume-role-policy-document file://trust-policy.json
```

Permissions policy:

```bash
cat > watchtower-scan-policy.json <<'EOF'
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:HeadObject"],
      "Resource": "arn:aws:s3:::watchtower-source-cache/*"
    },
    {
      "Effect": "Allow",
      "Action": ["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage",
                 "sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],
      "Resource": "arn:aws:sqs:us-east-1:111122223333:watchtower-scan-queue.fifo"
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

aws iam put-role-policy --role-name watchtower-scan-role \
  --policy-name watchtower-scan-policy --policy-document file://watchtower-scan-policy.json
```

`scripts/provision-aws.sh` also reconciles no-action CloudWatch alarms for PR/upload queue depth,
projection update failures, and a missing runtime-metrics heartbeat. Alarm notifications remain
deliberately unattached until an SNS/PagerDuty destination is selected.

---

## 4. Kubernetes ServiceAccount + `deploy.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: watchtower-sa
  namespace: watchtower
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/watchtower-scan-role
```

Then in the pod spec:
- add `serviceAccountName: watchtower-sa`
- add env vars `S3_BUCKET`, `SQS_QUEUE_URL` (from a ConfigMap/Secret once the queue exists), and
  `AWS_REGION=us-east-1`
- **no** `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

**Known risk, repo-side, not AWS-side:** `deploy.sh:259-322` currently overwrites some resource
fields from the live deployment on every redeploy. Before this goes live, someone should confirm
it does **not** also strip `serviceAccountName` the same way — otherwise the first redeploy after
this is wired up silently drops IRSA. Flag this back to me when you're ready and I'll check/fix
`deploy.sh` before it matters.

---

## 5. Repository Scan queue and report storage (release 2026.1.1)

A second FIFO queue carries repository scan work. All scans share one message group, so SQS
hands them out one at a time across every pod; jobs (repository sync, run preparation, exports)
use their own groups. Retention is 14 days because a large scheduled run can queue for a day or
more; the visibility timeout is extended by a heartbeat while a scan runs.

**`scripts/provision-aws.sh --env dev|prod` does everything in this section** (queue + DLQ,
role permissions including `s3:ListBucket`, so an expired report reads as missing rather than
access denied, and the `reports/`/`exports/` lifecycle rules). Run it with `--dry-run` first.
The commands below are the manual equivalent.

```bash
aws sqs create-queue --queue-name watchtower-reposcan-dlq.fifo --attributes FifoQueue=true

RS_DLQ_ARN=$(aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name watchtower-reposcan-dlq.fifo \
    --query QueueUrl --output text) \
  --attribute-names QueueArn --query Attributes.QueueArn --output text)

aws sqs create-queue --queue-name watchtower-reposcan.fifo --attributes '{
  "FifoQueue": "true",
  "ContentBasedDeduplication": "false",
  "VisibilityTimeout": "300",
  "MessageRetentionPeriod": "1209600",
  "RedrivePolicy": "{\"deadLetterTargetArn\":\"'"$RS_DLQ_ARN"'\",\"maxReceiveCount\":\"5\"}"
}'
```

Add to the role policy (same actions as the PR queue), plus S3 access for the new prefixes
(copy, used for unchanged rescans, needs GetObject and PutObject):

```json
{ "Effect": "Allow",
  "Action": ["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage",
             "sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],
  "Resource": "arn:aws:sqs:us-east-1:111122223333:watchtower-reposcan.fifo" },
{ "Effect": "Allow",
  "Action": ["s3:GetObject","s3:PutObject"],
  "Resource": ["arn:aws:s3:::watchtower-source-cache/reports/*",
               "arn:aws:s3:::watchtower-source-cache/exports/*"] }
```

Reports hold findings only (rule, file, line, message), never source code. Lifecycle rules for
the two new prefixes, added alongside the existing `source/` rule:

```json
{ "ID": "reports-retention", "Filter": {"Prefix": "reports/"}, "Status": "Enabled",
  "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
  "Expiration": {"Days": 400} },
{ "ID": "exports-retention", "Filter": {"Prefix": "exports/"}, "Status": "Enabled",
  "Expiration": {"Days": 7} }
```

Then set `watchtower.reposcan.queue-url` (env `WATCHTOWER_REPOSCAN_QUEUEURL`, Spring's relaxed
binding of that property) to the new queue's URL. Before running more than one replica, also set
`watchtower.cluster.multi-pod=true`, so a pod refuses to start without the queue and S3.

---

## What to hand back once this exists

Just three things, and Phase 3/4's actual code can start:
1. The S3 bucket name (if different from `watchtower-source-cache`)
2. The SQS queue URL
3. The IAM role ARN

## Summary table (for reference)

| Resource | Needed by | Notes |
|----------|-----------|-------|
| S3 bucket | 3.1–3.6 | Lifecycle rule on `source/`, encrypted, blocked public access |
| SQS FIFO queue + DLQ | 4.1–4.7 | Dedup off, visibility timeout ≈ max scan duration, DLQ after 3 receives |
| IAM role `watchtower-scan-role` + OIDC trust policy | 3.1, 4.1 | Least-privilege, scoped to `watchtower-sa` in the `watchtower` namespace |
| `ServiceAccount watchtower-sa` + `deploy.yaml` wiring | 3.1, 4.1 | Also needs `deploy.sh` checked so it doesn't strip `serviceAccountName` on redeploy |

## 6. AI rules assistant R1

Assistant chat needs no SQS queue. An accepted turn is committed to the database and immediately
wakes a bounded local worker on the pod that accepted it (`watchtower.assistant.workers`, 1–8).
Shared JPA claims, leases and heartbeats stop two pods from running the same turn. Each pod also
polls every 5 seconds (`watchtower.assistant.recovery-delay-ms`) to pick up missed wake-ups and
turns abandoned by a stopped pod. Set `watchtower.cluster.multi-pod=true` with multiple pods;
shared S3 is still required then, because any pod may resume a checkpoint. A
`watchtower-assistant.fifo` queue/DLQ created by an earlier provisioner run is unused. The
provisioner no longer creates it or grants access to it, and it never deletes it, so remove it by
hand once no older pods are running. Disabled deployments can start without any assistant resources.

The drawer receives progress and final answers over Server-Sent Events
(`GET /assistant/turn/{id}/events`). It falls back to 2-second polling when a stream is refused or
closed. Each pod serves at most `watchtower.assistant.max-streams` (default 64) streams and sends a
keepalive comment every 15 seconds. Streams close after 10 minutes and the browser reconnects, so
the ALB's default 60-second idle timeout is enough. Responses set `X-Accel-Buffering: no`; any
other proxy in front of the pods must not buffer `text/event-stream`.
Chat has no deployment flag: it is controlled only from the UI. It answers once an Assistant Admin
turns **Chat on** in Assistant settings and a working OpenAI key is stored; until then the drawer,
shown to everyone with Assistant Use, says what is missing. The OpenAI API key is not deployment configuration: an
Assistant Admin adds, replaces, tests or removes it under Assistant admin → AI integration. It is stored
in the `ai_integrations` table through the same encrypting converter as Bitbucket and ECR credentials,
so it is encrypted only when `watchtower.encryption.type=environment` is configured (with `none` it is
stored unencrypted, as those credentials are). The approved endpoint is the OpenAI HTTPS Responses API.

Assistant objects are encrypted with SSE-AES256 and stored under
`assistant/conversations/{sessionId}/{turnId}/{checkpointId}.json.gz`. Each checkpoint includes all
bounded recovery context. RDS keeps coordination, usage, hashes and pointers, without prompts/source.
The default retention is 14 days from the last accepted user message. History reads, ratings and
worker progress do not extend it. Expired history/continuation is denied immediately. A separate
minute task handles stuck/expired turns without touching transcript objects.

At 03:00 UTC daily, a ShedLock-protected job marks expired artifact versions with
`watchtower-retention=expired`. It rechecks session publication locks and current pointers before
marking old unpublished artifacts. S3 lifecycle owns physical deletion: current tagged versions
expire after they are at least one day old, noncurrent tagged versions expire after one day
noncurrent, and a prefix-only rule removes expired delete markers. No untagged active transcript
has an age-based expiry rule. Once marked, S3 deletion continues while pods are down; chats that
expire while every pod is down are marked after Watchtower returns. Lifecycle is asynchronous,
so physical removal can lag application expiry by several days. A later daily check confirms
that **all** exact-key versions and delete markers are gone before marking the transcript purged.
Pending lifecycle removal is normal and does not emit deletion-failure warnings.

IAM requires prefix-scoped ListBucketVersions and Get/PutObjectTagging plus
Get/PutObjectVersionTagging. The helper below attaches exactly these, limited to
`assistant/conversations/*`, as the inline policy `WatchtowerAssistantRetention` on the scan role;
without it the daily check fails on every transcript (as it did on Dev until 1 November 2026) and the
failure code does not say which S3 operation was refused. Daily failures emit one sanitized batch warning and RETENTION_FAILED
audit records; failed checks rotate behind unmarked objects. V086 adds the small retention-check
metadata field/index. Migration testing remains user-owned.

For an **existing bucket**, use the dedicated helper; it preserves unrelated lifecycle rules
(including AWS Security Agent inputs) and their transition-size setting. Its default is a read-only
preview. Select the normal Dev/Prod AWS profile explicitly:

```bash
python3 scripts/assistant_retention_config.py --bucket watchtower-source-cache --role watchtower-scan-role --profile <dev-profile>
# After reviewing the printed target role and rules, apply:
python3 scripts/assistant_retention_config.py --bucket watchtower-source-cache --role watchtower-scan-role --profile <dev-profile> --apply
```

Apply the policy/permissions and deploy the complete build including V086. The baseline provisioner
also includes these rules for fresh setup; do not rerun baseline provisioning solely to change
retention on an existing bucket. No AWS resource is changed merely by editing/testing the scripts.
Do not replace this tagged policy with unconditional 14-day expiry: it could delete older messages
from a continued chat. Increasing retention extends currently active chats; already expired chats
cannot be resurrected after their objects may have been handed to S3 lifecycle. Local development
without S3 deletes expired local files in the same daily job.

Use `/admin/assistant` with Assistant Admin to configure explicitly validated model capabilities,
efforts, pricing, limits and retention. Model discovery never enables a model. Record the organization's
actual provider data controls; `store=false` is not proof of Zero Data Retention. Reviewed feedback,
review decisions, fixture references and source-free audits follow the security team's ordinary
structured-record retention policy, independently of the expiring chat exception. No repository
archive or copied original regression source is created.

Before enabling chat, record a controlled Responses request/answer evaluation for every allowed
model/effort and the organization’s endpoint data controls. Set each input capability to the
validated model context limit; do not understate it to fit a budget. Every provider attempt reserves
that full input limit plus the configured output limit, because encrypted reasoning cannot be
reliably token-counted locally. Set turn/user/organization caps high enough for one such reservation
and the intended retry policy. Known usage refunds the difference once; uncertain requests retain
the full charge. A lower budget stops work explicitly. Discovery alone supplies none of this evidence.

Validate V060–V066 and the packaged engine layouts during the agreed Dev deployment checks.
The local deterministic and isolated browser suites use fixtures/stubs and establish protocol,
access, recovery and UI behavior; they do not establish live account access or answer accuracy.

## AWS Security Agent MVP (separate, opt-in provisioning)

Run the Security Agent setup mode after creating an Agent Space with code review, the input
bucket connection and service role, and after the baseline Watchtower IRSA/bucket setup:

```bash
# Preview only (read-only AWS calls; no output file or resources written)
bash scripts/provision-aws.sh --env dev --aws-security-only --dry-run
# Apply: asks for the account ID before making changes
bash scripts/provision-aws.sh --env dev --aws-security-only
# Production uses its own profile/account/bucket and discovers its own Space ID/role
bash scripts/provision-aws.sh --env prod --aws-security-only
```

Defaults are region `us-east-1`, space name `watchtower-dev-agent` / `watchtower-prod-agent`,
IRSA role `watchtower-scan-role`, and the existing environment-specific source-cache bucket.
Use `--aws-security-space-name NAME` (or `--aws-security-space-id ID`) for another space.
If multiple service roles are connected, select one with `--aws-security-service-role ARN`.
The script refuses missing/ambiguous spaces, foreign roles/accounts, unsupported encryption,
unconnected buckets, incompatible queue attributes and denied preflight reads before mutations.
It does not create a new Agent Space, role, bucket or AWS–SCM connection.

This mode discovers the Space ID/ARN and configured service role, checks service trust and
bucket ownership/region/encryption, creates the dedicated FIFO/DLQ, and reconciles two named
inline policies: `watchtower-aws-security-runtime-policy` on IRSA and
`watchtower-aws-security-input-policy` on the service role. Existing role trust and other
policies are preserved. The runtime role calls Security Agent; the service assumes its own
role. No cross-role `sts:AssumeRole` or blanket `iam:PassRole` grant is added. SSE-S3 adds no
KMS grants; a bucket configured with a full KMS key ARN gets matching scoped key permissions
(key policy/service access still requires the canary). The script verifies every created
queue and policy. A rerun reconciles partial success without creating duplicate queues.
Preflight and apply require the corresponding IAM GetRole/GetRolePolicy/PutRolePolicy,
Security Agent List/BatchGetAgentSpaces, S3 HeadBucket/GetBucketLocation/GetEncryptionConfiguration,
and SQS GetQueueUrl/GetQueueAttributes/CreateQueue permissions in the selected account.

After verified apply it writes `.aws-security/<env>.json` (gitignored, contains resource
references only). `deploy.sh <dev|prod>` automatically validates and loads that file, including
the runtime ServiceAccount annotation. Keep it on the machine running deployment, or pass
`WATCHTOWER_AWS_SECURITY_CONFIG_FILE=/path/to/<env>.json`. Cross-environment files fail before
a build/push. Without the file, deployment clears the Dev Security Agent references and
keeps activation off. Shared bucket/queue defaults and the IRSA annotation are also rendered
for the selected environment, so production no longer receives those Dev references.
Deployment remains a separate command. Generated settings never enable scans or choose the
failure policy: the checked-in activation flags stay false and `UNDECIDED`; change them only
after the documented acceptance gates.

The Security Agent mode does not change source lifecycle, role trust, log retention, alarms,
OIDC or Kubernetes state. Those checks, migration validation and the live canary remain gates.
Actual provisioning is owner-run, per the owner's latest instruction. The assistant completed
read-only Dev discovery/dry runs; no successful provisioning apply was recorded.
The existing `watchtower-source-cache` bucket can be reused under an isolated input prefix;
its SSE-S3 default is supported when `WATCHTOWER_AWS_SECURITY_KMS_KEY` is empty (owner-approved
2026-10-14). A separate bucket and KMS key are not required for this mode.
Code changes and read-only validation do not create AWS resources; apply the command above explicitly.

Required resources and scoped access:

| Resource/principal | Required configuration |
| --- | --- |
| Agent Space | Explicit supported region/account, isolated pilot scope, recorded code-review quotas |
| Input bucket | Same account/region; private access, block public access, TLS required; default SSE-S3 with an empty `kms-key`, or default SSE-KMS with the configured full key ARN; installation-specific `aws-security-inputs/<installation>/` prefix |
| Source lifecycle | One-day expiration on that prefix only; noncurrent-version expiration and expired delete-marker cleanup; abort incomplete multipart uploads; do not extend source lifetime using report retention |
| Runtime IRSA role | `sts:GetCallerIdentity`; Security Agent actions listed below; input `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`; bucket `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetEncryptionConfiguration`; only for SSE-KMS inputs, KMS `GenerateDataKey`/`Decrypt` on the configured key |
| Service role | Trust `securityagent.amazonaws.com` with `aws:SourceAccount` and Agent Space `aws:SourceArn` restrictions; read only the approved input prefix and access configured assessment logs; add KMS decrypt when reading SSE-KMS inputs; no SCM or assistant permissions |
| Logs | Custom group is optional: blank `log-group` omits API `logConfig`; AWS may create its default execution log group. Review service log permissions and retention before activation |
| Queue | Dedicated `watchtower-aws-security.fifo` plus FIFO DLQ, 180-second initial visibility, 14-day retention, redrive threshold 5; runtime Send/Receive/Delete/ChangeMessageVisibility/GetQueueAttributes on these exact ARNs |
| Reports | Existing shared S3 report store, `reports/aws-security/` prefix; existing source-free report retention. Runtime has read/write access, service role has none |

Runtime Security Agent actions are `BatchGetAgentSpaces`, `CreateCodeReview`,
`UpdateCodeReview`, `BatchGetCodeReviews`, `ListCodeReviews`, `StartCodeReviewJob`, `BatchGetCodeReviewJobs`,
`ListCodeReviewJobsForCodeReview`, `StopCodeReviewJob`, `ListFindings`, `BatchGetFindings`,
and `BatchDeleteCodeReviews`. Scope each action to the Agent Space where the current
[IAM reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_securityagent.html)
supports that resource. The current reference scopes all these runtime actions to AgentSpace;
PassRole dependencies belong to space/application setup operations and are not granted to the
pod by this script. Validate actual service access in Dev; do not infer permissions from a
successful bucket HEAD or policy readback.

`WATCHTOWER_AWS_SECURITY_MAX_CONCURRENT_REVIEWS` sets the initial shared active review limit
(default 2, supported range 1–5). Administrators can change this on the AWS Security Agent
setup page; V005 stores the override in the database so all pods use the same value without
a deployment. V004 adds permit rows 2–5; existing in-flight reviews keep their original row.
Keep the limit below the account/Region's available AWS code-review capacity. Extra requests remain
queued and do not occupy worker threads while AWS runs.

Use the current [Agent Space service-role trust instructions](https://docs.aws.amazon.com/securityagent/latest/userguide/create-iam-role.html),
not preview AgentInstance/AgentEnvironment ARNs. IAM role policy and bucket policy must
permit the service's source read, plus KMS key policy when using SSE-KMS inputs. Configure encryption, DLQ/oldest-message,
quota and cleanup-age alarms before approving source export. No deployment flags should
turn on PR enforcement until the AWS failure/timeout policy is decided.

For the existing SSE-S3 bucket, set `WATCHTOWER_AWS_SECURITY_INPUT_BUCKET=watchtower-source-cache`
and leave `WATCHTOWER_AWS_SECURITY_KMS_KEY` empty. With the default installation name, connect
`s3://watchtower-source-cache/aws-security-inputs/watchtower/` in the Agent Space and scope its
service role to that prefix. Preserve all other prefix retention rules when adding the input
lifecycle. The current provisioning script replaces the bucket lifecycle; its configuration
must include the additional rule before a subsequent run. Encryption readiness and verified
uploads do not replace the service-role access canary.

AWS Security Agent alarm templates can be prepared without AWS access using
`scripts/prepare-aws-security-alarms.py`.
The generator supports the dedicated FIFO/DLQ and exact account-provided `UsageMetric`
metadata for exposed quotas. Review/deploy alarms separately; it does not provision resources
or send notifications. Configure the verified AWS web-app domain and canary-qualified source
risk types as described in that runbook. Static access keys are not required: Watchtower uses
its IRSA role and Security Agent uses the separate source-reader service role.

A custom CloudWatch group is not required for this setup. AWS documents automatic default
execution logs when no group is selected; leaving the setting blank does not disable AWS
logging. See [optional code-review logging](https://docs.aws.amazon.com/securityagent/latest/userguide/enable-code-review-scan.html).
