import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("alarms", Path(__file__).with_name("prepare-aws-security-alarms.py"))
alarms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alarms)


class AlarmTemplateTest(unittest.TestCase):
    def test_queue_dimensions_and_dlq_metric(self):
        resources = alarms.template("review.fifo", "review-dlq.fifo", "dev")["Resources"]
        self.assertEqual(2, len(resources))
        self.assertEqual("ApproximateNumberOfMessagesVisible", resources["DeadLetterMessages"]["Properties"]["MetricName"])
        self.assertEqual([], resources["DeadLetterMessages"]["Properties"]["AlarmActions"])

    def test_exposed_metric_uses_exact_metadata_and_requires_period(self):
        quota = {"Quota": {"Value": 10, "UsageMetric": {"MetricNamespace": "AWS/Usage", "MetricName": "ResourceCount", "MetricDimensions": {"Service": "fixture", "Resource": "fixture"}, "MetricStatisticRecommendation": "Maximum"}}}
        with self.assertRaises(ValueError):
            alarms.template("q.fifo", "d.fifo", "dev", quota=quota)
        alarm = alarms.template("q.fifo", "d.fifo", "dev", quota=quota, quota_period=60)["Resources"]["ExposedQuotaUsage"]["Properties"]
        self.assertEqual("100 * usage / 10", alarm["Metrics"][1]["Expression"])
        self.assertEqual("fixture", alarm["Metrics"][0]["MetricStat"]["Metric"]["Dimensions"][0]["Value"])

    def test_unexposed_quota_is_refused_and_queues_must_be_distinct(self):
        with self.assertRaises(ValueError):
            alarms.template("q.fifo", "d.fifo", "dev", quota={"Value": 10}, quota_period=60)
        with self.assertRaises(ValueError):
            alarms.template("q.fifo", "q.fifo", "dev")


if __name__ == "__main__":
    unittest.main()
