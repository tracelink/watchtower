import copy
import json
import unittest
import tempfile
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

import provision_aws_security as provisioning
from aws_security_deploy_config import load_settings, apply_settings


CONFIG = provisioning.Config("111122223333", "us-east-1", "space-123", "watchtower-source-cache", "watchtower-scan-role")


SERVICE_ROLE = "arn:aws:iam::111122223333:role/service-role/security-test"


class FakeAws:
    def __init__(self):
        self.calls = []
        self.account = CONFIG.account
        self.spaces = [{"agentSpaceId": CONFIG.space_id, "name": "watchtower-dev-agent",
                        "awsResources": {"iamRoles": [SERVICE_ROLE], "s3Buckets": [CONFIG.bucket]},
                        "codeReviewSettings": {"generalPurposeScanning": True}}]
        self.sse = {"SSEAlgorithm": "AES256"}
        self.service_policy = None
        self.trust = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "securityagent.amazonaws.com"},
                                    "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": CONFIG.account},
                                    "ArnLike": {"aws:SourceArn": f"arn:aws:securityagent:{CONFIG.region}:{CONFIG.account}:agent-space/*"}}}]}
        self.queues = {}
        self.policy = None
        self.denied = None
        self.lost_create_response = False

    @staticmethod
    def argument(arguments, flag):
        return arguments[arguments.index(flag) + 1]

    @staticmethod
    def error(service, operation, code):
        return provisioning.AwsError(service, operation, f"An error occurred ({code}) when calling {operation}")

    def __call__(self, service, operation, *arguments):
        self.calls.append((service, operation, arguments))
        if self.denied == (service, operation):
            raise self.error(service, operation, "AccessDenied")
        if (service, operation) == ("sts", "get-caller-identity"):
            return {"Account": self.account}
        if (service, operation) == ("iam", "get-role"):
            name = self.argument(arguments, "--role-name")
            return {"Role": {"RoleName": name, "Arn": SERVICE_ROLE if name == "security-test" else f"arn:aws:iam::{CONFIG.account}:role/{name}",
                             "AssumeRolePolicyDocument": self.trust}}
        if (service, operation) == ("securityagent", "list-agent-spaces"):
            return {"agentSpaceSummaries": self.spaces}
        if (service, operation) == ("securityagent", "batch-get-agent-spaces"):
            return {"agentSpaces": self.spaces}
        if (service, operation) == ("s3api", "get-bucket-location"):
            return {"LocationConstraint": None}
        if (service, operation) == ("s3api", "get-bucket-encryption"):
            return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": self.sse}]}}
        if (service, operation) == ("s3api", "head-bucket"):
            return {}
        if (service, operation) == ("sqs", "get-queue-url"):
            name = self.argument(arguments, "--queue-name")
            if name not in self.queues:
                raise self.error(service, operation, "AWS.SimpleQueueService.NonExistentQueue")
            return {"QueueUrl": CONFIG.queue_url(name)}
        if (service, operation) == ("sqs", "get-queue-attributes"):
            name = self.argument(arguments, "--queue-url").rsplit("/", 1)[1]
            return {"Attributes": self.queues[name]}
        if (service, operation) == ("sqs", "create-queue"):
            name = self.argument(arguments, "--queue-name")
            self.queues[name] = {**json.loads(self.argument(arguments, "--attributes")), "QueueArn": CONFIG.queue_arn(name)}
            if self.lost_create_response:
                self.lost_create_response = False
                raise self.error(service, operation, "RequestTimeout")
            return {"QueueUrl": CONFIG.queue_url(name)}
        if (service, operation) == ("iam", "get-role-policy"):
            policy = self.service_policy if self.argument(arguments, "--policy-name") == provisioning.SERVICE_POLICY else self.policy
            if policy is None:
                raise self.error(service, operation, "NoSuchEntity")
            return {"PolicyDocument": copy.deepcopy(policy)}
        if (service, operation) == ("iam", "put-role-policy"):
            name = self.argument(arguments, "--policy-name")
            policy = json.loads(self.argument(arguments, "--policy-document"))
            if name == provisioning.POLICY:
                self.policy = policy
            elif name == provisioning.SERVICE_POLICY:
                self.service_policy = policy
            else:
                raise AssertionError("Overwriting unrelated policy")
            return {}
        raise AssertionError(f"Unexpected AWS operation: {service} {operation}")

    @property
    def mutations(self):
        return [call for call in self.calls if call[1].startswith(("create-", "put-", "update-", "delete-", "set-"))]


class ProvisionAwsSecurityTest(unittest.TestCase):
    def setUp(self):
        self.sleep = patch.object(provisioning.time, "sleep").start()
        self.output = patch("builtins.print").start()
        self.addCleanup(patch.stopall)

    def test_dry_run_never_mutates(self):
        aws = FakeAws()
        provisioning.provision(aws, CONFIG, dry_run=True)
        self.assertEqual([], aws.mutations)
        self.assertIsNone(aws.policy)
        self.assertEqual({}, aws.queues)

    def test_create_is_bounded_scoped_and_idempotent(self):
        aws = FakeAws()
        provisioning.provision(aws, CONFIG)
        self.assertEqual(["create-queue", "create-queue", "put-role-policy", "put-role-policy"], [call[1] for call in aws.mutations])
        self.assertEqual([provisioning.DLQ, provisioning.QUEUE], list(aws.queues))
        source = aws.queues[provisioning.QUEUE]
        self.assertEqual("180", source["VisibilityTimeout"])
        self.assertEqual("1209600", source["MessageRetentionPeriod"])
        self.assertEqual("false", source["ContentBasedDeduplication"])
        self.assertEqual({"deadLetterTargetArn": CONFIG.queue_arn(provisioning.DLQ), "maxReceiveCount": 5}, json.loads(source["RedrivePolicy"]))
        self.assertTrue(all(queue["FifoQueue"] == "true" and queue["SqsManagedSseEnabled"] == "true" for queue in aws.queues.values()))
        statements = {statement["Sid"]: statement for statement in aws.policy["Statement"]}
        self.assertEqual(CONFIG.space_arn, statements["SecurityAgentReviews"]["Resource"])
        self.assertEqual("arn:aws:s3:::watchtower-source-cache/aws-security-inputs/watchtower/*", statements["SecurityAgentInputs"]["Resource"])
        self.assertEqual(CONFIG.queue_arn(provisioning.QUEUE), statements["SecurityAgentQueue"]["Resource"])
        self.assertFalse(any(action in {"sts:AssumeRole", "iam:PassRole"} for statement in statements.values() for action in statement["Action"]))
        aws.calls.clear()
        provisioning.provision(aws, CONFIG)
        self.assertEqual([], aws.mutations)

    def test_wrong_account_or_space_stops_before_mutation(self):
        for field, value in (("account", "000000000000"), ("spaces", [])):
            with self.subTest(field=field):
                aws = FakeAws()
                setattr(aws, field, value)
                with self.assertRaises(ValueError):
                    provisioning.provision(aws, CONFIG)
                self.assertEqual([], aws.mutations)

    def test_denied_reads_are_not_treated_as_missing_resources(self):
        for denied in (("iam", "get-role"), ("s3api", "head-bucket"), ("sqs", "get-queue-url"), ("iam", "get-role-policy")):
            with self.subTest(denied=denied):
                aws = FakeAws()
                aws.denied = denied
                with self.assertRaises(provisioning.AwsError):
                    provisioning.provision(aws, CONFIG)
                self.assertEqual([], aws.mutations)

    def test_incompatible_existing_queue_stops_before_creating_missing_dlq(self):
        aws = FakeAws()
        aws.queues[provisioning.QUEUE] = {**provisioning.queue_attributes(CONFIG, provisioning.QUEUE),
                                          "QueueArn": CONFIG.queue_arn(provisioning.QUEUE), "VisibilityTimeout": "300"}
        before = copy.deepcopy(aws.queues)
        with self.assertRaisesRegex(ValueError, "VisibilityTimeout"):
            provisioning.provision(aws, CONFIG)
        self.assertEqual(before, aws.queues)
        self.assertEqual([], aws.mutations)

    def test_partial_creation_can_be_reconciled_without_duplicate_queue(self):
        aws = FakeAws()
        aws.lost_create_response = True
        with self.assertRaises(provisioning.AwsError):
            provisioning.provision(aws, CONFIG)
        self.assertEqual([provisioning.DLQ], list(aws.queues))
        aws.calls.clear()
        provisioning.provision(aws, CONFIG)
        creates = [call for call in aws.calls if call[1] == "create-queue"]
        self.assertEqual(1, len(creates))
        self.assertEqual(provisioning.QUEUE, aws.argument(creates[0][2], "--queue-name"))

    def test_invalid_identifiers_rejected_before_aws_access(self):
        aws = FakeAws()
        invalid = provisioning.Config(CONFIG.account, CONFIG.region, "*", CONFIG.bucket, CONFIG.role)
        with self.assertRaises(ValueError):
            provisioning.provision(aws, invalid)
        self.assertEqual([], aws.calls)

    def test_discovery_uses_exact_name_and_rejects_ambiguous_or_missing_references(self):
        config = replace(CONFIG, space_id="", space_name="watchtower-dev-agent")
        aws = FakeAws()
        # Other spaces before the match must not influence selection.
        aws.spaces.insert(0, {"agentSpaceId": "unrelated", "name": "other-agent"})
        self.assertEqual(CONFIG.space_id, provisioning.discover(aws, config).space_id)
        for mutation in (lambda a: a.spaces.clear(), lambda a: a.spaces.append(copy.deepcopy(a.spaces[0])),
                         lambda a: a.spaces[0]["awsResources"]["iamRoles"].append(SERVICE_ROLE + "2"),
                         lambda a: a.spaces[0]["awsResources"]["s3Buckets"].clear(),
                         lambda a: a.spaces[0].update(codeReviewSettings={})):
            with self.subTest(mutation=mutation):
                aws = FakeAws()
                mutation(aws)
                with self.assertRaises(ValueError):
                    provisioning.provision(aws, config)
                self.assertEqual([], aws.mutations)

    def test_foreign_role_or_incompatible_service_trust_stops_before_writes(self):
        for case in ("account", "trust", "source"):
            aws = FakeAws()
            if case == "account":
                aws.spaces[0]["awsResources"]["iamRoles"] = [SERVICE_ROLE.replace(CONFIG.account, "000000000000")]
            elif case == "trust":
                aws.trust["Statement"][0]["Principal"]["Service"] = "ec2.amazonaws.com"
            else:
                aws.trust["Statement"][0]["Condition"]["StringEquals"]["aws:SourceAccount"] = "000000000000"
            with self.subTest(case=case), self.assertRaises(ValueError):
                provisioning.provision(aws, CONFIG)
            self.assertEqual([], aws.mutations)

    def test_encryption_is_discovered_without_changing_bucket_or_granting_unneeded_kms(self):
        aws = FakeAws()
        resolved = provisioning.discover(aws, CONFIG)
        self.assertEqual("", resolved.kms_key)
        self.assertNotIn("kms:", json.dumps(provisioning.runtime_policy(resolved)))
        key = f"arn:aws:kms:{CONFIG.region}:{CONFIG.account}:key/key-123"
        aws.sse = {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key}
        resolved = provisioning.discover(aws, CONFIG)
        self.assertEqual(key, resolved.kms_key)
        self.assertEqual(["kms:Decrypt"], provisioning.service_policy(resolved)["Statement"][-1]["Action"])
        self.assertEqual(key, provisioning.runtime_policy(resolved)["Statement"][-1]["Resource"])
        for sse in ({"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "alias/test"}, {"SSEAlgorithm": "aws:kms:dsse"}):
            aws.sse = sse
            with self.assertRaises(ValueError):
                provisioning.provision(aws, CONFIG)
        self.assertEqual([], aws.mutations)

    def test_artifact_is_only_written_after_verified_apply_and_cannot_cross_environments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dev.json"
            aws = FakeAws()
            provisioning.provision(aws, CONFIG, dry_run=True, output_path=path)
            self.assertFalse(path.exists())
            aws.denied = ("iam", "put-role-policy")
            with self.assertRaises(provisioning.AwsError):
                provisioning.provision(aws, CONFIG, output_path=path)
            self.assertFalse(path.exists())
            aws.denied = None
            provisioning.provision(aws, CONFIG, output_path=path)
            data = load_settings(path, "dev", CONFIG.account, CONFIG.region)
            self.assertEqual(SERVICE_ROLE, data["settings"]["WATCHTOWER_AWS_SECURITY_SERVICE_ROLE"])
            for env, account, region in (("prod", "444455556666", CONFIG.region),
                                         ("dev", CONFIG.account, "us-west-2")):
                with self.assertRaises(ValueError):
                    load_settings(path, env, account, region)
            data["settings"]["WATCHTOWER_AWS_SECURITY_ENABLED"] = "true"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_settings(path, "dev", CONFIG.account, CONFIG.region)

    def test_portal_origin_is_validated_and_environment_bound(self):
        origin = "https://app-example.securityagent.global.app.aws"
        cfg = replace(CONFIG, web_app_url=origin)
        cfg.validate()
        self.assertEqual(origin, provisioning.deployment_settings(cfg)["WATCHTOWER_AWS_SECURITY_WEB_APP_URL"])
        for invalid in ("http://unsafe.example", "https://user:pass@portal.example", "https://portal.example/?token=x", "https://portal.example/code-reviews/one"):
            with self.assertRaises(ValueError):
                replace(CONFIG, web_app_url=invalid).validate()
        container = {"env": [{"name": "WATCHTOWER_AWS_SECURITY_WEB_APP_URL", "value": origin}]}
        docs = [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [container]}}}}]
        apply_settings(docs, None, "444455556666", CONFIG.region, "prod")
        self.assertFalse(any(e["name"] == "WATCHTOWER_AWS_SECURITY_WEB_APP_URL" for e in docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]))

    def test_deployment_does_not_copy_dev_references_or_activate_enforcement(self):
        docs = [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"env": [
            {"name": "WATCHTOWER_AWS_SECURITY_ACCOUNT", "value": CONFIG.account},
            {"name": "WATCHTOWER_AWS_SECURITY_ENABLED", "value": "true"},
            {"name": "watchtower.storage.s3.bucket", "value": CONFIG.bucket},
            {"name": "unrelated", "value": "preserve-me"},
        ]}]}}}}, {"kind": "ServiceAccount", "metadata": {"name": "watchtower-sa"}}]
        apply_settings(docs, None, "444455556666", CONFIG.region, "prod")
        env = {e["name"]: e["value"] for e in docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertNotIn("WATCHTOWER_AWS_SECURITY_ACCOUNT", env)
        self.assertNotIn("WATCHTOWER_AWS_SECURITY_ENABLED", env)
        self.assertNotIn("WATCHTOWER_AWS_SECURITY_CANARY_APPROVED", env)
        self.assertEqual("false", env["WATCHTOWER_AWS_SECURITY_PR_ENFORCEMENT"])
        self.assertEqual("UNDECIDED", env["WATCHTOWER_AWS_SECURITY_FAILURE_POLICY"])
        self.assertEqual("preserve-me", env["unrelated"])
        self.assertEqual("watchtower-source-cache-prod", env["watchtower.storage.s3.bucket"])
        self.assertIn("444455556666", docs[1]["metadata"]["annotations"]["eks.amazonaws.com/role-arn"])


if __name__ == "__main__":
    unittest.main()
