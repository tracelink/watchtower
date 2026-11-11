#!/usr/bin/env python3
"""Configure only assistant lifecycle/tagging permissions; preserve other bucket rules."""
import argparse
import copy
import json
import re
import subprocess

TAG = {"Key": "watchtower-retention", "Value": "expired"}
POLICY_NAME = "WatchtowerAssistantRetention"


def lifecycle_rules():
    return [
        {"ID": "assistant-expired-transcripts", "Status": "Enabled",
         "Filter": {"And": {"Prefix": "assistant/conversations/", "Tags": [TAG.copy()]}},
         "Expiration": {"Days": 1}, "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
        {"ID": "assistant-incomplete-uploads", "Status": "Enabled",
         "Filter": {"Prefix": "assistant/conversations/"},
         "Expiration": {"ExpiredObjectDeleteMarker": True},
         "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}},
    ]


def merge_lifecycle(existing):
    managed = {rule["ID"] for rule in lifecycle_rules()}
    result = {"Rules": [copy.deepcopy(rule) for rule in existing.get("Rules", [])
                        if rule.get("ID") not in managed]}
    result["Rules"].extend(lifecycle_rules())
    if len(result["Rules"]) > 1000:
        raise ValueError("Bucket lifecycle rule limit reached")
    return result


def runtime_policy(bucket):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ValueError("Invalid bucket name")
    arn = f"arn:aws:s3:::{bucket}"
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:ListBucketVersions"], "Resource": arn,
         "Condition": {"StringLike": {"s3:prefix": "assistant/conversations/*"}}},
        {"Effect": "Allow", "Action": ["s3:GetObjectTagging", "s3:GetObjectVersionTagging",
                                        "s3:PutObjectTagging", "s3:PutObjectVersionTagging"],
         "Resource": f"{arn}/assistant/conversations/*"},
    ]}


class Aws:
    def __init__(self, profile=None):
        self.prefix = ["aws", "--no-cli-pager"] + (["--profile", profile] if profile else [])

    def __call__(self, service, operation, *args):
        result = subprocess.run(self.prefix + [service, operation, *args, "--output", "json"],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            if operation == "get-bucket-lifecycle-configuration" and "NoSuchLifecycleConfiguration" in result.stderr:
                return {"Rules": []}
            # Keep credentials, response bodies and CLI diagnostics out of ordinary output.
            raise RuntimeError(f"AWS {service} {operation} failed; check the selected profile's permissions")
        return json.loads(result.stdout or "{}")


def configure(aws, bucket, role, dry_run=True):
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role):
        raise ValueError("Invalid runtime role name")
    policy = runtime_policy(bucket)
    aws("s3api", "head-bucket", "--bucket", bucket)
    identity = aws("iam", "get-role", "--role-name", role)["Role"]["Arn"]
    existing = aws("s3api", "get-bucket-lifecycle-configuration", "--bucket", bucket)
    lifecycle = merge_lifecycle(existing)
    if not dry_run:
        # Permissions first: tags are inert until the scoped lifecycle rule exists.
        aws("iam", "put-role-policy", "--role-name", role, "--policy-name", POLICY_NAME,
            "--policy-document", json.dumps(policy))
        options = (["--transition-default-minimum-object-size", existing["TransitionDefaultMinimumObjectSize"]]
                   if existing.get("TransitionDefaultMinimumObjectSize") else [])
        aws("s3api", "put-bucket-lifecycle-configuration", "--bucket", bucket,
            "--lifecycle-configuration", json.dumps(lifecycle), *options)
    return {"dryRun": dry_run, "bucket": bucket, "runtimeRoleArn": identity,
            "lifecycle": lifecycle, "runtimePolicy": policy}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--apply", action="store_true", help="Apply the two scoped changes; default is read-only")
    args = parser.parse_args()
    print(json.dumps(configure(Aws(args.profile), args.bucket, args.role, not args.apply), indent=2))


if __name__ == "__main__":
    main()
