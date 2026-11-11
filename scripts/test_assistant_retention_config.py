import copy
import json
import re
import unittest
from pathlib import Path
import assistant_retention_config as retention


class FakeAws:
    def __init__(self):
        self.calls = []
        self.existing = {"Rules": [{"ID": "aws-security-inputs", "Status": "Enabled",
                                   "Filter": {"Prefix": "aws-security-inputs/"}, "Expiration": {"Days": 1}}],
                         "TransitionDefaultMinimumObjectSize": "varies_by_storage_class"}

    def __call__(self, service, operation, *args):
        self.calls.append((service, operation, args))
        if operation == "get-role":
            return {"Role": {"Arn": "arn:aws:iam::123456789012:role/runtime"}}
        if operation == "get-bucket-lifecycle-configuration":
            return copy.deepcopy(self.existing)
        return {}


class AssistantRetentionConfigTest(unittest.TestCase):
    def test_rules_only_expire_tagged_transcripts_and_cover_versions_and_markers(self):
        expiry, markers = retention.lifecycle_rules()
        self.assertEqual({"And": {"Prefix": "assistant/conversations/", "Tags": [retention.TAG]}}, expiry["Filter"])
        self.assertEqual({"Days": 1}, expiry["Expiration"])
        self.assertEqual({"NoncurrentDays": 1}, expiry["NoncurrentVersionExpiration"])
        self.assertEqual({"Prefix": "assistant/conversations/"}, markers["Filter"])
        self.assertEqual({"ExpiredObjectDeleteMarker": True}, markers["Expiration"])
        self.assertNotIn("Days", markers["Expiration"])

    def test_merge_preserves_other_rules_and_is_idempotent(self):
        aws = FakeAws()
        original = copy.deepcopy(aws.existing)
        merged = retention.merge_lifecycle(aws.existing)
        self.assertEqual(original, aws.existing)
        self.assertEqual(original["Rules"][0], merged["Rules"][0])
        self.assertEqual(merged, retention.merge_lifecycle(merged))

    def test_default_dry_run_makes_only_reads_and_apply_writes_only_scoped_changes(self):
        aws = FakeAws()
        preview = retention.configure(aws, "test-bucket", "runtime")
        self.assertTrue(preview["dryRun"])
        self.assertFalse(any(op.startswith("put-") for _, op, _ in aws.calls))
        aws.calls.clear()
        retention.configure(aws, "test-bucket", "runtime", dry_run=False)
        self.assertEqual(["head-bucket", "get-role", "get-bucket-lifecycle-configuration", "put-role-policy", "put-bucket-lifecycle-configuration"], [op for _, op, _ in aws.calls])
        args = aws.calls[-1][2]
        written = json.loads(args[args.index("--lifecycle-configuration") + 1])
        self.assertEqual(aws.existing["Rules"][0], written["Rules"][0])
        self.assertIn("varies_by_storage_class", args)
        policy = preview["runtimePolicy"]["Statement"]
        self.assertTrue(all("Delete" not in action for item in policy for action in item["Action"]))
        self.assertEqual("arn:aws:s3:::test-bucket/assistant/conversations/*", policy[1]["Resource"])

    def test_invalid_targets_fail_before_any_aws_call(self):
        aws = FakeAws()
        for bucket, role in [("test-bucket", "../role"), ("invalid/bucket", "runtime")]:
            with self.assertRaises(ValueError):
                retention.configure(aws, bucket, role, False)
        self.assertEqual([], aws.calls)

    def test_baseline_provisioning_has_matching_rules(self):
        script = Path(__file__).with_name("provision-aws.sh").read_text()
        text = script.split("--lifecycle-configuration '", 1)[1].split("}'", 1)[0] + "}"
        text = re.sub(r"'\"\$[A-Z_]+\"'", "7", text)
        rules = json.loads(text)["Rules"]
        actual = [r for r in rules if r["ID"].startswith("assistant-")]
        self.assertEqual(retention.lifecycle_rules(), actual)


if __name__ == "__main__":
    unittest.main()
