# Runbook RB-S4 — Stolen EC2 instance-role credentials (`lab-web-role`)

| Field | Value |
|---|---|
| Scenario | S4 — SSRF in the web app + IMDSv1 → temporary credentials of `lab-web-role` stolen and used outside AWS |
| Framework | ISO/IEC 27035-1 incident phases · MITRE ATT&CK T1552.005, T1078.004, T1530 |
| Owner | Ziad Abbassi (incident lead + responder in this lab) |
| Response type | **Manual** (L3 only closes IMDSv1; it can't revoke credentials already stolen) |
| Pre-authorized actions | Steps 4.1–4.2 can be done **without approval** (see rules-of-engagement.md) |
| Clock | All times in **UTC** |

**Key fact:** instance-role credentials are **temporary** (`ASIA...` + session token, valid up to several hours). They **cannot be deactivated or deleted** like an access key. The only way to kill them before they expire is to **revoke the role's sessions**.

---

## 1. Plan and prepare
- [ ] Wazuh rules loaded: **100133**, **100130**, 100131, 100132; `seclab-instance-ips` updated after every apply (`scripts\update_instance_ip.ps1`) — otherwise 100130 can't tell the instance from an attacker.
- [ ] Know the blast radius of `lab-web-role` now: S3 read on the data bucket, `kms:Decrypt` on the data key, SSM core, **`ssm:GetParameter` on the Tailscale auth key**.
- [ ] Evidence folder `evidence/raw/` (git-ignored).

## 2. Detect and report
| Source | Signal | Severity |
|---|---|---|
| Wazuh **100133** (level 14) | IMDSv1-delivered `lab-web-role` creds used **outside** the instance | **Critical** |
| Wazuh **100130** (level 13) | `lab-web-role` creds used from an IP that isn't the instance | Critical |
| Wazuh 100132 (level 10) | IMDSv1 re-enabled on an instance (the precondition) | Medium → watch |
| Wazuh 100131 (level 9) | IMDSv1-delivered creds used (inside the instance) | Low → precursor |
| App / web logs | requests to `169.254.169.254` through the app (SSRF) | High |

**Record immediately** (incident ID `INC-<yyyymmdd>-S4`): alert time, rule ID, `accessKeyId` (`ASIA...`), session name (= instance ID), `sourceIPAddress`, `eventName`, `userAgent`, `ec2RoleDelivery`.

## 3. Assess and decide
1. Is the source IP the instance's own public IP? (`terraform output web_public_ip`). If **no** → the credentials are being used elsewhere → confirmed compromise.
2. `sessionContext.ec2RoleDelivery = 1.0` → creds came from **IMDSv1** → the SSRF path is open right now; the attacker can fetch fresh creds again.
3. **Decision rule:** confirmed → revoke sessions **and** close IMDSv1 together. Revoking alone is useless if IMDSv1 + SSRF stay open (the attacker just steals new creds).

## 4. Respond

### 4.1 Contain — revoke every session issued before now
Equivalent of the console button *IAM → Roles → lab-web-role → Revoke active sessions*. It adds a deny for all tokens issued **before** this moment; new tokens (issued after the fix) keep working.
```powershell
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$pol = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],"Condition":{"DateLessThan":{"aws:TokenIssueTime":"' + $now + '"}}}]}'
Set-Content "$env:TEMP\revoke.json" $pol -Encoding ascii
aws iam put-role-policy --role-name lab-web-role --policy-name AWSRevokeOlderSessions --policy-document "file://$env:TEMP\revoke.json"
Write-Host "Sessions issued before $now are now denied"
```
Side effect: the **instance itself** also loses its current creds until EC2 hands it new ones (minutes). Expect short SSM / agent hiccups — acceptable.

### 4.2 Contain — close the theft path (same minute as 4.1)
```powershell
$id = terraform -chdir=terraform output -raw web_instance_id
aws ec2 modify-instance-metadata-options --instance-id $id --http-tokens required --http-endpoint enabled
aws ec2 describe-instances --instance-ids $id --query "Reservations[].Instances[].MetadataOptions.HttpTokens" --output text
```
Must print `required`. Then re-enable the L3 rule so nobody can quietly flip it back:
```powershell
aws events enable-rule --name seclab-l3-imds-enforce
```

### 4.3 Collect evidence
```powershell
$inc = "INC-$(Get-Date -Format yyyyMMdd)-S4"
$dir = "evidence\raw\$inc"; New-Item -ItemType Directory -Force $dir | Out-Null
$key = "<STOLEN_ASIA_KEY_ID>"

# Management events made with the stolen key (regional + IAM)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$key --output json > "$dir\events-eu-north-1.json"
aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$key --output json > "$dir\events-us-east-1.json"

# Data events (which customer files were read)
aws s3 sync "s3://seclab-trail-111122223333/AWSLogs/111122223333/CloudTrail/" "$dir\trail"
python scripts\trail_events.py "$dir\trail" | Select-String $key | Out-File "$dir\data-events-by-key.txt"

# Integrity of the trail
aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:eu-north-1:111122223333:trail/seclab-trail --start-time <INCIDENT_START_UTC> > "$dir\validate-logs.txt"

Get-ChildItem $dir -Recurse -File | Get-FileHash -Algorithm SHA256 | Format-Table Hash, Path -AutoSize | Out-File "$dir\SHA256SUMS.txt"
```
Optional, for a real forensic case: snapshot the root volume **before** changing the instance (`aws ec2 create-snapshot --volume-id <vol> --description $inc`; a few cents — delete it after the report).

On the instance (SSM session), capture the app's access log showing the SSRF requests, then hash it:
```bash
sudo grep -n "169.254.169.254" /var/log/seclab-app/*.log | tee /tmp/ssrf-evidence.txt; sha256sum /tmp/ssrf-evidence.txt
```

**Answer from the evidence:**
- Time window of malicious use, attacker IPs, user agents.
- **Data read:** `clients-s3.csv` and/or `clients-kms.csv` (the role can decrypt the KMS copy → both are exposed in S4, unlike S1).
- **Was the Tailscale auth key read?** Look for `GetParameter` on `/seclab/tailscale-authkey` with the stolen key. If yes → revoke it in the Tailscale admin console and check *Machines* for unknown devices (attacker could have joined the tailnet that reaches Wazuh).

### 4.4 Eradicate
- Remove the vulnerable route: `terraform apply` with `vuln_app=false` (and `imds_v1=false`).
- If the Tailscale key was read: revoke it, generate a new one, store it with masked input (`Read-Host -AsSecureString`), remove unknown tailnet devices.
- If anything was created with the stolen creds (unlikely with this role's rights): remove it.

### 4.5 Recover
- Keep `AWSRevokeOlderSessions` on the role until the instance is replaced (it only blocks old tokens). For a clean state: `terraform apply` recreates the instance from the fixed config, then delete the inline policy:
  ```powershell
  aws iam delete-role-policy --role-name lab-web-role --policy-name AWSRevokeOlderSessions
  ```
- Watch Wazuh **100130 / 100133** for 24 h; any hit after revocation = new theft path, reopen.

## 5. Learn lessons
| Root cause / gap | Corrective control | Framework |
|---|---|---|
| IMDSv1 allowed on the instance | IMDSv2 required + hop limit 1; **account default** `aws ec2 modify-instance-metadata-defaults --http-tokens required` (Phase 5); L3 auto-enforcement | ISO 27001 A.8.9 · CIS AWS 5.x (EC2 IMDSv2) |
| SSRF in the app | Input validation / allow-list of outbound URLs, block link-local `169.254.0.0/16` from the app | A.8.28, A.8.26 |
| Role could read data **and** a network join secret | Split roles; Tailscale key with tag + ACL (EC2 → Wazuh 1514/1515 only) | A.5.15, A.8.2, A.8.20 |
| Stolen temp creds valid for hours | Shorter role session where possible; detection 100130/100133 as compensating control | A.8.16 |

**Metrics to record:** time to detect (first outside use → 100130/100133 alert), time to contain (alert → sessions revoked + IMDSv2), files read.

## 6. Closure checklist
- [ ] `AWSRevokeOlderSessions` applied (or instance replaced) and confirmed: a stolen-token call now returns `AccessDenied` (check in CloudTrail `errorCode`).
- [ ] IMDSv2 `required`, L3 rule enabled, vulnerable route removed.
- [ ] Tailscale key question answered (read or not), revoked if read.
- [ ] Evidence hashed, report written (`reports/incidents/<inc>.md`), lessons in the risk register.

## 7. Timeline template
| UTC time | Source | Event | Actor / IP | Action taken |
|---|---|---|---|---|
| | App log | SSRF request to `169.254.169.254` | | |
| | CloudTrail | first call with stolen `ASIA...` key outside AWS | | |
| | Wazuh 100133 | alert | | incident opened |
| | Responder | `AWSRevokeOlderSessions` | | contained (creds dead) |
| | Responder | IMDSv2 required, L3 on | | contained (path closed) |
| | Responder | vuln route removed, instance replaced | | eradicated / recovered |
