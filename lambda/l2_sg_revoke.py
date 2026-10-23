"""L2 - S3 containment: revoke security-group ingress rules open to the whole internet.

Trigger (EventBridge, "AWS API Call via CloudTrail"):
  ec2 AuthorizeSecurityGroupIngress (no errorCode)

Scope: only security groups tagged Project=seclab (also enforced by the IAM policy condition).
Reads the group's CURRENT rules (not only the event), so it also catches rules added in
the same batch and is idempotent: if nothing is open anymore, it does nothing.
"""
import json
import os
from datetime import datetime, timezone

import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
PROJECT_TAG = os.environ.get("PROJECT_TAG", "seclab")
WORLD = {"0.0.0.0/0", "::/0"}


def notify(subject, body):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=json.dumps(body, indent=2))


def handler(event, context):
    d = event["detail"]
    gid = d.get("requestParameters", {}).get("groupId", "")
    result = {"lambda": "L2", "group_id": gid, "trigger": d.get("eventName"),
              "caller": d.get("userIdentity", {}).get("arn"), "source_ip": d.get("sourceIPAddress"),
              "event_time": d.get("eventTime")}

    if not gid:
        result["action"] = "skipped: no groupId in event"
        print(json.dumps(result))
        return result

    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
    if tags.get("Project") != PROJECT_TAG:
        result["action"] = "skipped: not a seclab security group"
        print(json.dumps(result))
        return result

    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [gid]}])["SecurityGroupRules"]
    open_rules = [r for r in rules if not r.get("IsEgress")
                  and (r.get("CidrIpv4") in WORLD or r.get("CidrIpv6") in WORLD)]

    if not open_rules:
        result["action"] = "skipped: no internet-open ingress left (already fixed)"
        print(json.dumps(result))
        return result

    ec2.revoke_security_group_ingress(GroupId=gid,
                                      SecurityGroupRuleIds=[r["SecurityGroupRuleId"] for r in open_rules])

    now = datetime.now(timezone.utc)
    result["action"] = f"REMEDIATED: revoked {len(open_rules)} internet-open ingress rule(s)"
    result["revoked"] = [{"rule_id": r["SecurityGroupRuleId"], "protocol": r.get("IpProtocol"),
                          "from": r.get("FromPort"), "to": r.get("ToPort"),
                          "cidr": r.get("CidrIpv4") or r.get("CidrIpv6")} for r in open_rules]
    result["remediation_time"] = now.isoformat()
    if d.get("eventTime"):
        t0 = datetime.fromisoformat(d["eventTime"].replace("Z", "+00:00"))
        result["seconds_from_change_to_fix"] = round((now - t0).total_seconds(), 1)

    notify(f"[seclab L2] Internet-open ingress revoked on {gid}", result)
    print(json.dumps(result))
    return result
