"""Summarize downloaded CloudTrail log files.

Usage (from the repo root, after syncing the trail bucket into evidence/raw/):
    python scripts/trail_events.py evidence/raw/phase1
Shows: event counts by source/name, every IAM event, every S3 data event.
"""
import collections
import gzip
import json
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence/raw")
files = [f for f in root.rglob("*.json.gz") if "CloudTrail-Digest" not in str(f)]
if not files:
    sys.exit(f"No CloudTrail log files under {root}")

records = []
for f in files:
    with gzip.open(f, "rt", encoding="utf-8") as fh:
        records.extend(json.load(fh).get("Records", []))

print(f"{len(files)} files, {len(records)} events\n")

counts = collections.Counter(f"{r['eventSource']}  {r['eventName']}" for r in records)
print("== Events by source / name ==")
for name, n in counts.most_common():
    print(f"{n:5}  {name}")


def line(r):
    who = r.get("userIdentity", {}).get("arn") or r.get("userIdentity", {}).get("type")
    return (f"{r['eventTime']}  {r['eventName']:<24} region={r.get('awsRegion')}  "
            f"ip={r.get('sourceIPAddress')}  who={who}  key={r.get('userIdentity', {}).get('accessKeyId', '-')}")


iam = sorted((r for r in records if r["eventSource"] == "iam.amazonaws.com"), key=lambda r: r["eventTime"])
print(f"\n== IAM events ({len(iam)}) ==")
for r in iam:
    print(line(r))

data = sorted((r for r in records if r.get("eventCategory") == "Data"), key=lambda r: r["eventTime"])
print(f"\n== S3 data events ({len(data)}) ==")
for r in data:
    print(line(r) + f"  object={r.get('requestParameters', {}).get('key')}")
