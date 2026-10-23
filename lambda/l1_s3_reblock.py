"""L1 - S1 containment: put S3 Block Public Access back on a seclab bucket.

Trigger (EventBridge, "AWS API Call via CloudTrail"):
  s3 PutBucketPublicAccessBlock / DeleteBucketPublicAccessBlock / PutBucketPolicy (no errorCode)

Loop guard (the fix itself is a PutBucketPublicAccessBlock call that triggers this rule again):
  1. ignore events made by this Lambda's own role
  2. read the current config first: if all four flags are already true, do nothing
"""
import json
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BUCKET_PREFIX = os.environ.get("BUCKET_PREFIX", "seclab-")
OWN_ROLE = os.environ.get("OWN_ROLE_NAME", "seclab-l1-s3-reblock")
FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def notify(subject, body):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=json.dumps(body, indent=2))


def handler(event, context):
    d = event["detail"]
    bucket = d.get("requestParameters", {}).get("bucketName", "")
    caller = d.get("userIdentity", {}).get("arn", "")
    result = {"lambda": "L1", "bucket": bucket, "trigger": d.get("eventName"),
              "caller": caller, "source_ip": d.get("sourceIPAddress"), "event_time": d.get("eventTime")}

    if not bucket.startswith(BUCKET_PREFIX):
        result["action"] = "skipped: not a seclab bucket"
        print(json.dumps(result))
        return result

    if f"assumed-role/{OWN_ROLE}/" in caller:
        result["action"] = "skipped: own remediation call (loop guard)"
        print(json.dumps(result))
        return result

    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        cfg = {}

    if cfg and all(cfg.get(f) for f in FLAGS):
        result["action"] = "skipped: Block Public Access already fully on (loop guard)"
        print(json.dumps(result))
        return result

    s3.put_public_access_block(Bucket=bucket,
                               PublicAccessBlockConfiguration={f: True for f in FLAGS})

    now = datetime.now(timezone.utc)
    result["action"] = "REMEDIATED: Block Public Access re-enabled (all 4 flags)"
    result["previous_config"] = cfg or "none (deleted)"
    result["remediation_time"] = now.isoformat()
    if d.get("eventTime"):
        t0 = datetime.fromisoformat(d["eventTime"].replace("Z", "+00:00"))
        result["seconds_from_change_to_fix"] = round((now - t0).total_seconds(), 1)

    notify(f"[seclab L1] S3 Block Public Access restored on {bucket}", result)
    print(json.dumps(result))
    return result
