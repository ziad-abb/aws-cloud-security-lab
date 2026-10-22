"""Turn saved CloudTrail log files into Wazuh test lines (same shape as the aws-s3 module).

Usage (repo root):
    python scripts/to_wazuh_lines.py evidence/raw/phase1 evidence/raw/phase1-wazuh.json [EventName ...]
Without EventName filters, all events are written. Example:
    python scripts/to_wazuh_lines.py evidence/raw/phase1 evidence/raw/s1-test.json GetObject HeadObject
"""
import gzip
import json
import sys
from pathlib import Path

src, dst, *names = sys.argv[1:] or ["evidence/raw", "evidence/raw/wazuh-lines.json"]
wanted = set(names)

count = 0
with open(dst, "w", encoding="utf-8") as out:
    for f in sorted(Path(src).rglob("*.json.gz")):
        if "CloudTrail-Digest" in str(f):
            continue
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            for rec in json.load(fh).get("Records", []):
                if wanted and rec.get("eventName") not in wanted:
                    continue
                rec["source"] = "cloudtrail"
                rec["log_info"] = {"log_file": f.name, "s3bucket": "test"}
                out.write(json.dumps({"integration": "aws", "aws": rec}, separators=(",", ":")) + "\n")
                count += 1

print(f"Wrote {count} lines to {dst}")
