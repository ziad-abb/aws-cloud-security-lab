#!/var/ossec/framework/python/bin/python3
"""Read CloudTrail log files in ARRIVAL order via SQS and write their events for Wazuh.

Why: the Wazuh aws-s3 module (polling mode) remembers the last processed file NAME and
skips files whose name sorts before it. CloudTrail writes data events in separate files
that can arrive late -> those files were skipped (S1 anonymous GetObject never ingested).
S3 -> SQS notifications are processed as they arrive, so nothing is skipped.

Output: one JSON object per line, same shape as the aws-s3 module and iam_poller.py:
    {"integration": "aws", "aws": {<CloudTrail record>, "source": "cloudtrail", ...}}

Runs as root (systemd timer, every minute) with the wazuh-reader profile.
A message is deleted only after its file was written, so a crash means a retry, not a loss
(after 5 failed receives SQS moves it to the dead-letter queue).
"""
import gzip
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import unquote_plus

import boto3

PROFILE = "wazuh-reader"
REGION = "eu-north-1"
QUEUE_NAME = "seclab-trail-events"
OUT_FILE = Path("/var/log/seclab/trail-events.json")
STATE_FILE = Path("/var/lib/seclab/trail_reader_state.json")
KEEP_KEYS = 1000       # remember recent object keys: SQS standard queues can deliver twice
MAX_RUNTIME = 50       # seconds: finish before the next timer tick (1 min)


def load_seen():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text()).get("keys", [])
    return []


def save_seen(keys):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"keys": keys[-KEEP_KEYS:]}))
    os.replace(tmp, STATE_FILE)


def main():
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    sqs = session.client("sqs")
    s3 = session.client("s3")
    queue_url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]

    seen = load_seen()
    seen_set = set(seen)
    files = events = 0
    start = time.time()

    while time.time() - start < MAX_RUNTIME:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10 if files == 0 else 2)
        messages = resp.get("Messages", [])
        if not messages:
            break

        for msg in messages:
            body = json.loads(msg["Body"])
            lines = []
            for rec in body.get("Records", []):          # s3:TestEvent has no Records -> just deleted
                if not rec.get("eventName", "").startswith("ObjectCreated"):
                    continue
                bucket = rec["s3"]["bucket"]["name"]
                key = unquote_plus(rec["s3"]["object"]["key"])
                if key in seen_set:
                    continue
                obj = s3.get_object(Bucket=bucket, Key=key)
                data = json.loads(gzip.decompress(obj["Body"].read()))
                for ct in data.get("Records", []):
                    ct["source"] = "cloudtrail"
                    ct["log_info"] = {"log_file": key, "s3bucket": bucket}
                    ct["seclab_feed"] = "trail-sqs"
                    lines.append(json.dumps({"integration": "aws", "aws": ct}, separators=(",", ":")))
                seen.append(key)
                seen_set.add(key)
                files += 1

            if lines:
                OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
                with OUT_FILE.open("a", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
                events += len(lines)

            # Delete only after the events are safely written.
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            save_seen(seen)

    print(f"trail_sqs_reader files={files} events={events} runtime={time.time() - start:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"trail_sqs_reader error: {exc}", file=sys.stderr)
        sys.exit(1)
