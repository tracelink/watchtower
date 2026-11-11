#!/usr/bin/env python3
"""Generate a reviewable CloudFormation alarm template locally. Never calls AWS or sends alerts."""
import argparse
import json
import math
import re
from pathlib import Path


def template(queue, dlq, prefix, topic=None, quota=None, quota_period=None):
    for value in (queue, dlq):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,75}\.fifo", value):
            raise ValueError("Use the dedicated FIFO queue and DLQ names")
    if queue == dlq or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", prefix):
        raise ValueError("Distinct queues and a bounded alarm prefix are required")
    if topic and not re.fullmatch(r"arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+", topic):
        raise ValueError("Invalid notification topic ARN")
    resources = {}
    for name, metric, queue_name, threshold in (
        ("DeadLetterMessages", "ApproximateNumberOfMessagesVisible", dlq, 1),
        ("QueueDelay", "ApproximateAgeOfOldestMessage", queue, 18000),
    ):
        resources[name] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "AlarmName": f"{prefix}-{name}", "Namespace": "AWS/SQS", "MetricName": metric,
            "Dimensions": [{"Name": "QueueName", "Value": queue_name}], "Statistic": "Maximum",
            "Period": 60, "EvaluationPeriods": 3, "DatapointsToAlarm": 2,
            "Threshold": threshold, "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching", "AlarmActions": [topic] if topic else [],
        }}
    if quota:
        # Input is the exact get-service-quota response from the target account/region.
        # No assumed Security Agent metric, dimensions, quota code or quota value.
        q = quota.get("Quota", quota)
        usage = q.get("UsageMetric") or {}
        limit = q.get("Value")
        dimensions = usage.get("MetricDimensions")
        statistic = usage.get("MetricStatisticRecommendation")
        if not isinstance(limit, (float, int)) or not math.isfinite(limit) or limit <= 0:
            raise ValueError("Quota must have a confirmed positive Value")
        if not usage.get("MetricNamespace") or not usage.get("MetricName") or not isinstance(dimensions, dict) or len(dimensions) > 30:
            raise ValueError("This quota has no supported UsageMetric; do not invent a usage alarm")
        if statistic not in {"Sum", "Maximum", "Average", "Minimum", "SampleCount"}:
            raise ValueError("A supported provider-recommended statistic is required")
        if quota_period is None or quota_period < 60 or quota_period > 86400 or quota_period % 60:
            raise ValueError("Confirm the usage metric period: 60–86400 seconds, a multiple of 60")
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in dimensions.items()):
            raise ValueError("Quota metric dimensions must be strings")
        resources["ExposedQuotaUsage"] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "AlarmName": f"{prefix}-ExposedQuotaUsage", "EvaluationPeriods": 2,
            "Threshold": 80, "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "missing", "AlarmActions": [topic] if topic else [],
            "Metrics": [
                {"Id": "usage", "ReturnData": False, "MetricStat": {"Metric": {
                    "Namespace": usage["MetricNamespace"], "MetricName": usage["MetricName"],
                    "Dimensions": [{"Name": k, "Value": v} for k, v in sorted(dimensions.items())],
                }, "Period": quota_period, "Stat": statistic}},
                {"Id": "percent", "Expression": f"100 * usage / {limit}", "Label": "Confirmed quota utilization (%)", "ReturnData": True},
            ],
        }}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Watchtower AWS Security Agent external alarms; review before deployment", "Resources": resources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue-name", required=True)
    parser.add_argument("--dlq-name", required=True)
    parser.add_argument("--alarm-prefix", required=True)
    parser.add_argument("--sns-topic-arn")
    parser.add_argument("--quota-json", type=Path)
    parser.add_argument("--quota-period-seconds", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        quota = json.loads(args.quota_json.read_text()) if args.quota_json else None
        result = template(args.queue_name, args.dlq_name, args.alarm_prefix, args.sns_topic_arn, quota, args.quota_period_seconds)
        # Avoid clobbering a previously reviewed template.
        with args.output.open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
