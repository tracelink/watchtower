#!/usr/bin/env python3
"""Dedicated Security Agent queues and additive runtime IAM, called by provision-aws.sh."""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path


QUEUE = "watchtower-aws-security.fifo"
DLQ = "watchtower-aws-security-dlq.fifo"
POLICY = "watchtower-aws-security-runtime-policy"
SERVICE_POLICY = "watchtower-aws-security-input-policy"
SECURITY_ACTIONS = [
    "BatchGetAgentSpaces", "CreateCodeReview", "BatchGetCodeReviews", "ListCodeReviews",
    "StartCodeReviewJob", "BatchGetCodeReviewJobs", "ListCodeReviewJobsForCodeReview",
    "StopCodeReviewJob", "ListFindings", "BatchGetFindings", "BatchDeleteCodeReviews",
    "UpdateCodeReview",
]


class AwsError(RuntimeError):
    def __init__(self, service, operation, stderr):
        match = re.search(r"An error occurred \(([^)]+)\)", stderr)
        self.code = match.group(1) if match else "AwsCliError"
        super().__init__(f"{service} {operation} failed: {stderr.strip()}")


class AwsCli:
    def __init__(self, region):
        self.region = region

    def __call__(self, service, operation, *arguments):
        result = subprocess.run(
            ["aws", "--region", self.region, "--no-cli-pager", "--output", "json",
             service, operation, *arguments],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode:
            raise AwsError(service, operation, result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else {}


@dataclass(frozen=True)
class Config:
    account: str
    region: str
    space_id: str
    bucket: str
    role: str
    installation: str = "watchtower"
    space_name: str = ""
    service_role: str = ""
    kms_key: str = ""
    web_app_url: str = ""

    def validate(self):
        for label, value, pattern in (
            ("account", self.account, r"[0-9]{12}"),
            ("region", self.region, r"[a-z]{2}-[a-z]+-[0-9]+"),
            ("space ID", self.space_id, r"[A-Za-z0-9_-]{0,128}"),
            ("bucket", self.bucket, r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
            ("role name", self.role, r"[A-Za-z0-9+=,.@_-]{1,64}"),
            ("installation", self.installation, r"[A-Za-z0-9_-]{1,64}"),
        ):
            if not re.fullmatch(pattern, value):
                raise ValueError(f"Invalid {label}")
        if self.service_role and not re.fullmatch(f"arn:aws:iam::{self.account}:role/[A-Za-z0-9/+=,.@_-]+", self.service_role):
            raise ValueError("Service role must belong to the selected account")
        if self.kms_key and not re.fullmatch(f"arn:aws:kms:{self.region}:{self.account}:key/[A-Za-z0-9-]+", self.kms_key):
            raise ValueError("Input KMS key must be a full key ARN in the selected account/region")

        if self.web_app_url and not re.fullmatch(r"https://[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/?", self.web_app_url):
            raise ValueError("AWS web app URL must be an HTTPS origin without path, credentials or query")

    @property
    def space_arn(self):
        return f"arn:aws:securityagent:{self.region}:{self.account}:agent-space/{self.space_id}"

    @property
    def prefix(self):
        return f"aws-security-inputs/{self.installation}/"

    def queue_arn(self, name):
        return f"arn:aws:sqs:{self.region}:{self.account}:{name}"

    def queue_url(self, name):
        return f"https://sqs.{self.region}.amazonaws.com/{self.account}/{name}"


def queue_attributes(config, name):
    attributes = {"FifoQueue": "true", "MessageRetentionPeriod": "1209600", "SqsManagedSseEnabled": "true"}
    if name == QUEUE:
        attributes.update({
            "ContentBasedDeduplication": "false", "VisibilityTimeout": "180",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": config.queue_arn(DLQ), "maxReceiveCount": 5}),
        })
    return attributes


def runtime_policy(config):
    bucket_arn = f"arn:aws:s3:::{config.bucket}"
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "SecurityAgentReviews", "Effect": "Allow",
         "Action": ["securityagent:" + action for action in SECURITY_ACTIONS], "Resource": config.space_arn},
        {"Sid": "SecurityAgentInputs", "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"],
         "Resource": bucket_arn + "/" + config.prefix + "*"},
        {"Sid": "SecurityAgentInputListing", "Effect": "Allow",
         "Action": ["s3:ListBucket", "s3:ListBucketVersions"], "Resource": bucket_arn,
         "Condition": {"StringLike": {"s3:prefix": config.prefix + "*"}}},
        {"Sid": "SecurityAgentBucketReadiness", "Effect": "Allow",
         "Action": ["s3:ListBucket", "s3:GetEncryptionConfiguration"], "Resource": bucket_arn},
        {"Sid": "SecurityAgentQueue", "Effect": "Allow",
         "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                    "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], "Resource": config.queue_arn(QUEUE)},
    ]}
    if config.kms_key:
        policy["Statement"].append({"Sid": "InputEncryption", "Effect": "Allow",
                                    "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": config.kms_key})
    return policy


def service_policy(config):
    bucket = f"arn:aws:s3:::{config.bucket}"
    statements = [
        {"Sid": "ReadWatchtowerInputs", "Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": bucket + "/" + config.prefix + "*"},
        {"Sid": "ListWatchtowerInputs", "Effect": "Allow", "Action": ["s3:ListBucket"],
         "Resource": bucket, "Condition": {"StringLike": {"s3:prefix": config.prefix + "*"}}},
    ]
    if config.kms_key:
        statements.append({"Sid": "DecryptWatchtowerInputs", "Effect": "Allow",
                           "Action": ["kms:Decrypt"], "Resource": config.kms_key})
    return {"Version": "2012-10-17", "Statement": statements}


def discover(aws, config):
    """Resolve exact environment references. Never pick the first unrelated space or role."""
    if not config.space_id:
        # AWS CLI auto-pagination returns the complete aggregate; do not use --max-items.
        spaces = aws("securityagent", "list-agent-spaces").get("agentSpaceSummaries", [])
        matches = [space for space in spaces if space.get("name") == config.space_name]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one Agent Space named {config.space_name!r}; found {len(matches)}. "
                             "Create/configure it first, or supply --aws-security-space-name / --aws-security-space-id.")
        config = replace(config, space_id=matches[0]["agentSpaceId"])
    config.validate()
    spaces = aws("securityagent", "batch-get-agent-spaces", "--agent-space-ids", config.space_id).get("agentSpaces", [])
    matches = [space for space in spaces if space.get("agentSpaceId") == config.space_id]
    if len(matches) != 1:
        raise ValueError("Agent Space is not readable in the selected account/region")
    space = matches[0]
    resources = space.get("awsResources", {})
    roles = list(dict.fromkeys(resources.get("iamRoles", [])))
    selected = config.service_role or (roles[0] if len(roles) == 1 else "")
    if not selected or selected not in roles:
        raise ValueError("Select one connected service role with --aws-security-service-role; ambiguous/missing role")
    config = replace(config, service_role=selected, space_name=space.get("name", ""))
    config.validate()
    connected = resources.get("s3Buckets", [])
    approved = {config.bucket, f"s3://{config.bucket}", f"s3://{config.bucket}/",
                f"s3://{config.bucket}/{config.prefix}"}
    if not approved.intersection(connected):
        raise ValueError(f"Connect {config.bucket} or its exact input prefix to the Agent Space first")
    if not any(space.get("codeReviewSettings", {}).get(key) is True
               for key in ("controlsScanning", "generalPurposeScanning")):
        raise ValueError("Enable code review on the selected Agent Space first")
    role = aws("iam", "get-role", "--role-name", selected.rsplit("/", 1)[1]).get("Role", {})
    if role.get("Arn") != selected:
        raise ValueError("Unexpected service role identity")
    statements = role.get("AssumeRolePolicyDocument", {}).get("Statement", [])
    def includes(value, expected):
        return expected in (value if isinstance(value, list) else [value])
    def compatible(statement):
        conditions = statement.get("Condition", {})
        # Check the source restrictions when present; preserve the console's trust policy.
        for operator, entries in conditions.items():
            for key, values in entries.items():
                target = {"aws:SourceAccount": config.account, "aws:SourceArn": config.space_arn}.get(key)
                if target is None:
                    continue  # Other conditions still require the live service canary.
                values = values if isinstance(values, list) else [values]
                if operator in {"StringEquals", "ArnEquals"} and target not in values:
                    return False
                if operator in {"StringLike", "ArnLike"} and not any(fnmatch.fnmatchcase(target, v) for v in values):
                    return False
        return True
    if not any(s.get("Effect") == "Allow" and includes(s.get("Principal", {}).get("Service"), "securityagent.amazonaws.com")
               and includes(s.get("Action"), "sts:AssumeRole") and compatible(s) for s in statements):
        raise ValueError("Service role trust does not allow Security Agent for this account/space; trust was not changed")
    aws("s3api", "head-bucket", "--bucket", config.bucket, "--expected-bucket-owner", config.account)
    location = aws("s3api", "get-bucket-location", "--bucket", config.bucket, "--expected-bucket-owner", config.account).get("LocationConstraint") or "us-east-1"
    if location != config.region:
        raise ValueError("Input bucket is not in the selected region")
    rules = aws("s3api", "get-bucket-encryption", "--bucket", config.bucket, "--expected-bucket-owner", config.account).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    if len(rules) != 1:
        raise ValueError("Expected one explicit bucket default encryption rule")
    default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
    algorithm = default.get("SSEAlgorithm")
    if algorithm not in {"AES256", "aws:kms"}:
        raise ValueError(f"Unsupported input bucket encryption: {algorithm}")
    key = default.get("KMSMasterKeyID", "") if algorithm == "aws:kms" else ""
    if algorithm == "aws:kms" and not key.startswith("arn:aws:kms:"):
        raise ValueError("Bucket default KMS setting must use a full key ARN to match application readiness")
    config = replace(config, kms_key=key)
    config.validate()
    return config


def deployment_settings(config):
    settings = {"WATCHTOWER_AWS_SECURITY_" + key: value for key, value in {
        "ACCOUNT": config.account, "REGION": config.region, "SPACE_ID": config.space_id,
        "SERVICE_ROLE": config.service_role, "INPUT_BUCKET": config.bucket, "KMS_KEY": config.kms_key,
        "LOG_GROUP": "", "QUEUE_URL": config.queue_url(QUEUE), "INSTALLATION": config.installation,
    }.items()}
    if config.web_app_url:
        settings["WATCHTOWER_AWS_SECURITY_WEB_APP_URL"] = config.web_app_url
    return settings


def write_settings(path, config, environment, runtime_role_arn):
    artifact = {"schemaVersion": 1, "environment": environment, "account": config.account,
                "region": config.region, "agentSpaceName": config.space_name, "agentSpaceArn": config.space_arn,
                "runtimeRoleArn": runtime_role_arn, "dlqUrl": config.queue_url(DLQ),
                "settings": deployment_settings(config)}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temp_path = stream.name
        json.dump(artifact, stream, indent=2)
        stream.write("\n")
    os.replace(temp_path, path)
    print(f"Deployment settings saved to {path}; deploy.sh {environment} loads them automatically.")


def read_policy(aws, role, name):
    try:
        return aws("iam", "get-role-policy", "--role-name", role, "--policy-name", name).get("PolicyDocument")
    except AwsError as error:
        if error.code != "NoSuchEntity":
            raise
        return None


def inspect_queue(aws, config, name):
    try:
        result = aws("sqs", "get-queue-url", "--queue-name", name, "--queue-owner-aws-account-id", config.account)
    except AwsError as error:
        if error.code in {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}:
            return None
        raise
    url = result.get("QueueUrl")
    if url != config.queue_url(name):
        raise ValueError(f"Unexpected account/region in queue URL for {name}")
    actual = aws("sqs", "get-queue-attributes", "--queue-url", url, "--attribute-names", "All").get("Attributes", {})
    expected = {**queue_attributes(config, name), "QueueArn": config.queue_arn(name)}
    for key, value in expected.items():
        matches = actual.get(key) == value
        if key == "RedrivePolicy":
            redrive = json.loads(actual.get(key, "{}"))
            matches = (redrive.get("deadLetterTargetArn") == config.queue_arn(DLQ)
                       and str(redrive.get("maxReceiveCount")) == "5")
        if not matches:
            raise ValueError(f"Existing {name} has incompatible {key}; no existing queue attributes were changed")
    return url


def provision(aws, config, dry_run=False, environment="dev", output_path=None):
    config.validate()
    # Check all external references and existing resources before the first mutation.
    if aws("sts", "get-caller-identity").get("Account") != config.account:
        raise ValueError("AWS caller account does not match the selected environment")
    role = aws("iam", "get-role", "--role-name", config.role).get("Role", {})
    if not role.get("Arn", "").startswith(f"arn:aws:iam::{config.account}:role/") or role.get("RoleName") != config.role:
        raise ValueError("Unexpected runtime role identity")
    config = discover(aws, config)
    if config.service_role == role["Arn"]:
        raise ValueError("Runtime IRSA role and provider service role must be separate")
    queues = {name: inspect_queue(aws, config, name) for name in (DLQ, QUEUE)}
    policies = [(config.role, POLICY, runtime_policy(config)),
                (config.service_role.rsplit("/", 1)[1], SERVICE_POLICY, service_policy(config))]
    changes = [{"role": role_name, "name": name, "policy": policy}
               for role_name, name, policy in policies if read_policy(aws, role_name, name) != policy]
    print(json.dumps({"account": config.account, "region": config.region,
                      "queuesToCreate": {name: queue_attributes(config, name) for name, url in queues.items() if not url},
                      "agentSpaceName": config.space_name, "agentSpaceArn": config.space_arn,
                      "serviceRole": config.service_role, "inlinePolicyChanges": changes,
                      "deploymentSettings": deployment_settings(config)}, indent=2))
    if dry_run:
        print("Dry run: read-only checks passed; no resources changed.")
    else:
        for name, url in queues.items():
            if url:
                continue
            created = aws("sqs", "create-queue", "--queue-name", name,
                          "--attributes", json.dumps(queue_attributes(config, name)))
            if created.get("QueueUrl") != config.queue_url(name):
                raise ValueError(f"Unexpected created queue URL for {name}")
            # SQS requires a short propagation interval after creation; only poll reads.
            for _ in range(6):
                time.sleep(1)
                if inspect_queue(aws, config, name):
                    break
            else:
                raise ValueError(f"Could not verify new queue {name}; rerun to reconcile")
        for change in changes:
            aws("iam", "put-role-policy", "--role-name", change["role"], "--policy-name", change["name"],
                "--policy-document", json.dumps(change["policy"]))
            for attempt in range(6):
                if read_policy(aws, change["role"], change["name"]) == change["policy"]:
                    break
                time.sleep(1)
            else:
                raise ValueError("IAM policy verification failed; rerun to reconcile")
        if output_path:
            write_settings(output_path, config, environment, role["Arn"])
        print("Security Agent queues and scoped policies verified. No deployment or scan activation performed.")
    for name, value in deployment_settings(config).items():
        print(f"{name}={value}")
    print(f"DLQ_URL={config.queue_url(DLQ)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("account", "region", "bucket", "role", "environment", "output"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--space-id", default="")
    parser.add_argument("--space-name", default="")
    parser.add_argument("--service-role", default="")
    parser.add_argument("--installation", default="watchtower")
    parser.add_argument("--web-app-url", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        provision(AwsCli(args.region), Config(args.account, args.region, args.space_id, args.bucket, args.role,
                  args.installation, args.space_name, args.service_role, web_app_url=args.web_app_url), args.dry_run, args.environment, args.output)
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
