#!/var/ossec/framework/python/bin/python3
"""Poll the us-east-1 CloudTrail event history for IAM events and write them for Wazuh.

Why: the account is locked to eu-north-1 and multi-region trails are not allowed,
so global IAM events (CreateAccessKey, CreateUser, AttachUserPolicy...) never reach
the trail. They ARE available in the us-east-1 event history (LookupEvents).

Output: one JSON object per line, same shape as the Wazuh aws-s3 module output,
so Wazuh's built-in AWS decoder/rules and our custom rules apply unchanged:
    {"integration": "aws", "aws": {<CloudTrail record>, "source": "cloudtrail", ...}}

Runs as root (systemd timer) with the `wazuh-reader` profile in /root/.aws/credentials.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

PROFILE = "wazuh-reader"
REGION = "us-east-1"
OUT_FILE = Path("/var/log/seclab/iam-events.json")
STATE_FILE = Path("/var/lib/seclab/iam_poller_state.json")
FIRST_RUN_LOOKBACK = timedelta(hours=24)
OVERLAP = timedelta(minutes=5)   # event history lags a few minutes: re-read a window
KEEP_IDS = 2000                  # remember recent EventIds to avoid duplicates


def load_state():
    if STATE_FILE.exists():
        s = json.loads(STATE_FILE.read_text())
        return datetime.fromisoformat(s["last_time"]), set(s.get("seen_ids", []))
    return datetime.now(timezone.utc) - FIRST_RUN_LOOKBACK, set()


def save_state(last_time, seen_ids):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"last_time": last_time.isoformat(),
                               "seen_ids": list(seen_ids)[-KEEP_IDS:]}))
    os.replace(tmp, STATE_FILE)


def main():
    last_time, seen = load_state()
    start = last_time - OVERLAP
    end = datetime.now(timezone.utc)

    client = boto3.Session(profile_name=PROFILE).client("cloudtrail", region_name=REGION)
    paginator = client.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "iam.amazonaws.com"}],
        StartTime=start,
        EndTime=end,
    )

    new_events = []
    newest = last_time
    for page in pages:
        for ev in page.get("Events", []):
            if ev["EventId"] in seen:
                continue
            record = json.loads(ev["CloudTrailEvent"])
            record["source"] = "cloudtrail"
            record["log_info"] = {"log_file": "us-east-1-event-history", "s3bucket": "none"}
            record["seclab_feed"] = "iam-poller"
            new_events.append((ev["EventTime"], {"integration": "aws", "aws": record}))
            seen.add(ev["EventId"])
            if ev["EventTime"] > newest:
                newest = ev["EventTime"]

    # Oldest first, so Wazuh sees them in order.
    new_events.sort(key=lambda x: x[0])
    if new_events:
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with OUT_FILE.open("a", encoding="utf-8") as fh:
            for _, obj in new_events:
                fh.write(json.dumps(obj, separators=(",", ":")) + "\n")

    save_state(newest, seen)
    print(f"{datetime.now(timezone.utc).isoformat()} window={start.isoformat()}..{end.isoformat()} new={len(new_events)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # visible in journalctl, and the timer retries next run
        print(f"iam_poller error: {exc}", file=sys.stderr)
        sys.exit(1)
