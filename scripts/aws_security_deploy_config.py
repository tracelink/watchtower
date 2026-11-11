"""Validate provisioning output and apply environment-bound deployment settings."""
import json
import re
from pathlib import Path

from provision_aws_security import Config, deployment_settings


def load_settings(path, environment, account, region):
    path = Path(path)
    if not path.exists():
        return None
    artifact = json.loads(path.read_text())
    if any(artifact.get(key) != expected for key, expected in {
        "schemaVersion": 1, "environment": environment, "account": account, "region": region,
    }.items()):
        raise ValueError("Security Agent provisioning output belongs to a different environment/account/region")
    values = artifact["settings"]
    get = lambda key: values["WATCHTOWER_AWS_SECURITY_" + key]
    role = artifact["runtimeRoleArn"]
    config = Config(get("ACCOUNT"), get("REGION"), get("SPACE_ID"), get("INPUT_BUCKET"),
                    role.rsplit("/", 1)[1], get("INSTALLATION"), service_role=get("SERVICE_ROLE"), kms_key=get("KMS_KEY"), web_app_url=values.get("WATCHTOWER_AWS_SECURITY_WEB_APP_URL", ""))
    config.validate()
    if (not config.space_id or not config.service_role or config.account != account or config.region != region
            or not re.fullmatch(f"arn:aws:iam::{account}:role/[A-Za-z0-9/+=,.@_-]+", role)
            or artifact.get("agentSpaceArn") != config.space_arn or values != deployment_settings(config)):
        raise ValueError("Invalid or unsafe Security Agent provisioning output; rerun the provisioner")
    return artifact


def apply_settings(documents, artifact, account, region, environment):
    for doc in documents:
        if doc.get("kind") == "Deployment":
            container = doc["spec"]["template"]["spec"]["containers"][0]
            # Never let checked-in Dev references escape into a production deployment.
            resource_names = {"WATCHTOWER_AWS_SECURITY_" + key for key in (
                "ACCOUNT", "REGION", "SPACE_ID", "SERVICE_ROLE", "INPUT_BUCKET", "KMS_KEY", "LOG_GROUP", "QUEUE_URL", "INSTALLATION", "WEB_APP_URL")}
            obsolete_names = {"WATCHTOWER_AWS_SECURITY_ENABLED", "WATCHTOWER_AWS_SECURITY_CANARY_APPROVED", "WATCHTOWER_AWS_SECURITY_PROVIDER_RETENTION_DAYS"}
            env = [e for e in container.get("env", []) if e.get("name") not in resource_names | obsolete_names]
            if artifact:
                env.extend({"name": name, "value": value} for name, value in artifact["settings"].items())
            for key, value in {
                "PR_ENFORCEMENT": "false", "FAILURE_POLICY": "UNDECIDED",
            }.items():
                name = "WATCHTOWER_AWS_SECURITY_" + key
                existing = next((entry for entry in env if entry.get("name") == name), None)
                if existing is None:
                    env.append({"name": name, "value": value})
                elif artifact is None:
                    existing.pop("valueFrom", None)
                    existing["value"] = value
            container["env"] = env
            # Shared reports and baseline queues use the same environment as the AWS child.
            # These references were previously hard-coded to Dev in the manifest.
            baseline = {
                "watchtower.storage.s3.bucket": "watchtower-source-cache" if environment == "dev" else "watchtower-source-cache-prod",
                "watchtower.storage.s3.region": region,
                "watchtower.queue.sqs.queue-url": f"https://sqs.{region}.amazonaws.com/{account}/watchtower-scan-queue.fifo",
                "watchtower.queue.sqs.region": region,
                "watchtower.reposcan.queue-url": f"https://sqs.{region}.amazonaws.com/{account}/watchtower-reposcan.fifo",
            }
            for entry in env:
                if entry.get("name") in baseline:
                    entry.pop("valueFrom", None)
                    entry["value"] = baseline[entry["name"]]
        elif doc.get("kind") == "ServiceAccount" and doc["metadata"]["name"] == "watchtower-sa":
            doc["metadata"].setdefault("annotations", {})["eks.amazonaws.com/role-arn"] = (
                artifact["runtimeRoleArn"] if artifact else f"arn:aws:iam::{account}:role/watchtower-scan-role")
