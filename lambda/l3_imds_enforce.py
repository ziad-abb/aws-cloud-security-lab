"""L3 - IMDSv2 enforcement: force http_tokens=required on seclab instances.

Trigger (EventBridge, "AWS API Call via CloudTrail"):
  ec2 ModifyInstanceMetadataOptions / RunInstances (no errorCode)

Must be DISABLED during the S4 attack (lambdas_enabled=false), otherwise it closes IMDSv1
before the SSRF can use it.
Loop guard: the fix is itself a ModifyInstanceMetadataOptions call; on that second event the
instance is already "required", so nothing happens.
"""
import json
import os
from datetime import datetime, timezone

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
PROJECT_TAG = os.environ.get("PROJECT_TAG", "seclab")


def notify(subject, body):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=json.dumps(body, indent=2))


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def instance_ids(d):
    if d.get("eventName") == "ModifyInstanceMetadataOptions":
        req = d.get("requestParameters", {}).get("ModifyInstanceMetadataOptionsRequest", {})
        return [req["InstanceId"]] if req.get("InstanceId") else []
    if d.get("eventName") == "RunInstances":
        items = as_list(d.get("responseElements", {}).get("instancesSet", {}).get("items"))
        return [i["instanceId"] for i in items if i.get("instanceId")]
    return []


def handler(event, context):
    d = event["detail"]
    ids = instance_ids(d)
    result = {"lambda": "L3", "trigger": d.get("eventName"), "instances": ids,
              "caller": d.get("userIdentity", {}).get("arn"), "source_ip": d.get("sourceIPAddress"),
              "event_time": d.get("eventTime"), "fixed": [], "skipped": []}

    if not ids:
        result["action"] = "skipped: no instance id in event"
        print(json.dumps(result))
        return result

    reservations = ec2.describe_instances(InstanceIds=ids)["Reservations"]
    for inst in [i for r in reservations for i in r["Instances"]]:
        iid = inst["InstanceId"]
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        tokens = inst.get("MetadataOptions", {}).get("HttpTokens")
        if tags.get("Project") != PROJECT_TAG:
            result["skipped"].append({"instance": iid, "reason": "not a seclab instance"})
        elif tokens == "required":
            result["skipped"].append({"instance": iid, "reason": "already IMDSv2-only (loop guard)"})
        else:
            ec2.modify_instance_metadata_options(InstanceId=iid, HttpTokens="required",
                                                 HttpEndpoint="enabled")
            result["fixed"].append({"instance": iid, "previous_http_tokens": tokens})

    if not result["fixed"]:
        result["action"] = "nothing to fix"
        print(json.dumps(result))
        return result

    now = datetime.now(timezone.utc)
    result["action"] = f"REMEDIATED: IMDSv2 enforced on {len(result['fixed'])} instance(s)"
    result["remediation_time"] = now.isoformat()
    if d.get("eventTime"):
        t0 = datetime.fromisoformat(d["eventTime"].replace("Z", "+00:00"))
        result["seconds_from_change_to_fix"] = round((now - t0).total_seconds(), 1)

    notify(f"[seclab L3] IMDSv2 enforced on {', '.join(f['instance'] for f in result['fixed'])}", result)
    print(json.dumps(result))
    return result
