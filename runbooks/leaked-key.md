# Runbook RB-S2 — Leaked IAM access key (`dev-ci`)

| Field | Value |
|---|---|
| Scenario | S2 — long-term access key leaked (public repo / CI log), used by an attacker |
| Framework | ISO/IEC 27035-1 incident phases · MITRE ATT&CK T1078.004, T1098.001, T1530 |
| Owner | Ziad Abbassi (incident lead + responder in this lab) |
| Response type | **Manual** (no auto-remediation: disabling a key is a business decision) |
| Pre-authorized actions | Steps 4.1–4.3 can be done **without approval** (see rules-of-engagement.md) |
| Clock | All times in **UTC** |

---

## 1. Plan and prepare (before any incident)
- [ ] Responder workstation: AWS CLI with the `admin` profile, Python + `scripts/trail_events.py`.
- [ ] Wazuh rules loaded: **100110**, **100113**, 100111/100112, 100150 (see `wazuh/local_rules.xml`).
- [ ] IAM poller and trail SQS reader running on VM1 (IAM events come from the us-east-1 event history, not the trail).
- [ ] Evidence folder exists and is git-ignored: `evidence/raw/`.
- [ ] Know what `dev-ci` is allowed to do (blast radius) — read its policies **now**, not during the incident:
  ```powershell
  aws iam list-attached-user-policies --user-name dev-ci
  aws iam list-user-policies --user-name dev-ci
  ```

## 2. Detect and report
**Triggers (any one opens the incident):**

| Source | Signal | Severity |
|---|---|---|
| Wazuh **100110** (level 12) | `dev-ci` key used from an IP not in `seclab-known-ips` | High |
| Wazuh **100113** (level 14) | the leaked key **created a new access key** (persistence) | **Critical** |
| Wazuh 100150 (level 10) | any IAM user key used from an unknown IP | Medium → assess |
| External | TruffleHog / GitHub secret-scanning alert, AWS "exposed credentials" email | High |

**Record immediately** (incident ID `INC-<yyyymmdd>-S2`): alert time, rule ID, `accessKeyId`, `userName`, `sourceIPAddress`, `eventName`, `userAgent`. Start the timeline (section 7).

## 3. Assess and decide
1. **Is it really the leaked key?** Compare `aws.userIdentity.accessKeyId` with the key list:
   ```powershell
   aws iam list-access-keys --user-name dev-ci --query "AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]" --output table
   ```
   A key **you didn't create** = attacker persistence → severity **Critical**.
2. **Is the source IP legitimate?** (CI runner range, my own IPs). Unknown IP + key in a public place = confirmed incident.
3. **Decision rule:** confirmed or likely compromise → contain **now**. Containment is reversible (deny + deactivate, nothing deleted), so the cost of a false positive is minutes of CI downtime.

## 4. Respond

### 4.1 Contain — stop every key of the user at once (order matters)
`AWSDenyAll` blocks **all** keys of `dev-ci`, including ones the attacker created that you haven't found yet. Do it first.
```powershell
aws iam attach-user-policy --user-name dev-ci --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
```

### 4.2 Contain — deactivate (not delete) every key
Deactivated keys are kept as evidence and can be re-enabled if this was a false positive.
```powershell
$keys = aws iam list-access-keys --user-name dev-ci --query "AccessKeyMetadata[].AccessKeyId" --output text
foreach ($k in $keys -split "\s+") { aws iam update-access-key --user-name dev-ci --access-key-id $k --status Inactive; Write-Host "deactivated $k" }
```

### 4.3 Contain — persistence on OTHER identities
The attacker may have created keys or users elsewhere. Check `CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy` made **by `dev-ci`** (IAM events live in **us-east-1**):
```powershell
aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=Username,AttributeValue=dev-ci --query "Events[].[EventTime,EventName]" --output table
```
For every `CreateAccessKey` whose target user isn't `dev-ci`: deactivate that key the same way. For a new user: attach `AWSDenyAll` to it.

### 4.4 Collect evidence (before eradication)
```powershell
$inc = "INC-$(Get-Date -Format yyyyMMdd)-S2"
$dir = "evidence\raw\$inc"; New-Item -ItemType Directory -Force $dir | Out-Null
$key = "<LEAKED_KEY_ID>"

# Management events by key: eu-north-1 (regional APIs) + us-east-1 (IAM)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$key --output json > "$dir\events-eu-north-1.json"
aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$key --output json > "$dir\events-us-east-1.json"

# Data events (S3 GetObject...) are NOT in event history: read them from the trail bucket
aws s3 sync "s3://seclab-trail-111122223333/AWSLogs/111122223333/CloudTrail/" "$dir\trail"
python scripts\trail_events.py "$dir\trail" | Select-String $key | Out-File "$dir\data-events-by-key.txt"

# Prove the trail files were not altered (CloudTrail digest validation)
aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:eu-north-1:111122223333:trail/seclab-trail --start-time <INCIDENT_START_UTC> > "$dir\validate-logs.txt"

# Hash everything collected
Get-ChildItem $dir -Recurse -File | Get-FileHash -Algorithm SHA256 | Format-Table Hash, Path -AutoSize | Out-File "$dir\SHA256SUMS.txt"
```
On VM1, export the Wazuh alerts for the key:
```bash
sudo grep "<LEAKED_KEY_ID>" /var/ossec/logs/alerts/alerts.json > /tmp/inc-s2-alerts.json && sha256sum /tmp/inc-s2-alerts.json
```

**Answer these from the evidence (they go in the incident report):**
- First and last malicious call (UTC), source IPs, user agents.
- **Data accessed:** which objects were read (`GetObject` lines in `data-events-by-key.txt`). Fake PII in this lab — in real life this decides breach notification (law 09-08 / CNDP).
- Persistence created (keys, users, policies).

### 4.5 Eradicate
```powershell
# Delete the attacker-created key(s) and the leaked key (evidence already saved)
aws iam delete-access-key --user-name dev-ci --access-key-id <KEY_ID>
```
- Remove the secret from where it leaked (repo file, CI log). **Rewriting Git history is not enough** — the key is burnt the moment it was public; it must be rotated.
- Remove anything the attacker created (resources found in 4.3/4.4).

### 4.6 Recover
1. If CI still needs AWS access: create a **new** key, stored only in the CI secret store (never in code):
   ```powershell
   aws iam create-access-key --user-name dev-ci --query AccessKey.AccessKeyId --output text
   ```
   (Get the secret into the CI secret store without printing it on screen.)
2. Detach the deny policy once the new key is in place and the hunt is closed:
   ```powershell
   aws iam detach-user-policy --user-name dev-ci --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
   ```
3. Watch Wazuh **100110 / 100113** for 24 h.

## 5. Learn lessons
| Root cause / gap | Corrective control | Framework |
|---|---|---|
| Long-lived key existed at all | Replace with **OIDC federation** (GitHub Actions → IAM role, short-lived creds) | ISO 27001 A.5.17, A.8.5 · CIS AWS 2.x |
| Secret committed to a repo | Pre-commit + CI secret scanning (TruffleHog/gitleaks), GitHub push protection | A.8.4, A.8.28 |
| Key had more rights than CI needs | Least privilege on `dev-ci`, scoped to exact resources | A.5.15, A.8.2 |
| IAM events not in the regional trail | IAM poller on us-east-1 event history (in place) — residual risk documented | A.8.15, A.8.16 |

**Metrics to record:** time to detect (first malicious call → Wazuh alert), time to contain (alert → `AWSDenyAll`), data objects accessed.

## 6. Closure checklist
- [ ] All keys of `dev-ci` deactivated/deleted; no unknown key anywhere (`aws iam list-access-keys` for every user).
- [ ] No attacker-created identity or resource left.
- [ ] Evidence hashed, report written (`reports/incidents/<inc>.md`).
- [ ] Lessons-learned actions added to the risk register with an owner and a date.

## 7. Timeline template
| UTC time | Source | Event | Actor / IP | Action taken |
|---|---|---|---|---|
| | CloudTrail | first call with leaked key | | |
| | Wazuh 100110 | alert | | incident opened |
| | Responder | `AWSDenyAll` attached | | contained |
| | Responder | keys deactivated | | |
| | Responder | hunt done, persistence removed | | eradicated |
| | Responder | new key / OIDC, deny removed | | recovered |
