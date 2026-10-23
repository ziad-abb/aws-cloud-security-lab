# Rules of Engagement — AWS Cloud Security Lab

| Field | Value |
|---|---|
| Owner / approver | Ziad Abbassi (account owner, red team and blue team in this lab) |
| Valid for | Phase 4 attack runs (S1–S3), the IMDSv1 misconfiguration test (L3) and any rule-test triggers |
| Version / date | v2 — 2026-10-23 |

Purpose: write down **before** attacking what is allowed, against what, from where, and when to stop. Even when one person plays both sides, this is what separates a controlled test from an incident.

## 1. Scope

**In scope**
- AWS account **111122223333**, region **eu-north-1**, resources created by this repo's Terraform (tagged `Project=seclab`) plus the `dev-ci` IAM user created for S2.
- The lab EC2 instance (S3, IMDSv1 misconfiguration test).
- My own VMs (Wazuh VM1, Kali VM2) on my laptop.

**Out of scope (never touched)**
- Any other AWS account, any AWS-owned infrastructure, other customers' resources.
- My real accounts outside the lab (GitHub beyond this repo, email, Tailscale settings beyond the lab nodes).
- Any real personal data — only the synthetic Faker file (`data/clients.csv`) is used.

## 2. Allowed and forbidden techniques

**Allowed**
- S1: making the lab data bucket public via the Terraform toggle, anonymous `curl` reads of the two lab files.
- S2: using the `dev-ci` key from Kali/CloudShell: `sts get-caller-identity`, list/read the lab bucket, create one extra access key (persistence), TruffleHog against the lab repo.
- S3: opening tcp/22 via the toggle, **Hydra against the lab instance only**, time-boxed (below).
- IMDSv1 test: setting `imds_v1=true` via the toggle so L3 re-enforces IMDSv2 (no attack traffic).

**Forbidden** (in line with the AWS Customer Support Policy for Penetration Testing)
- Denial of service, flooding, stress tests, or any traffic designed to degrade a service.
- Attacking AWS endpoints themselves (beyond normal authenticated API calls), DNS zone walking, port scans of anything not mine.
- Social engineering, phishing, anything involving real people.
- Using the stolen or leaked credentials for anything beyond the scenario steps (no new resources, no privilege escalation attempts outside the plan).

**Rate / time limits**
- Hydra: max 4 parallel tasks (`-t 4`), a small wordlist (≤ 200 entries), **max 5 minutes** per run.
- Each scenario exposure window (bucket public, SSH open, IMDSv1 allowed) is **time-boxed to 60 minutes**, then reverted.

## 3. Identities and IPs
| Role | Identity | Source IP |
|---|---|---|
| Responder / admin | IAM user `admin` (CLI) | home IP (in `seclab-known-ips`) |
| Attacker | Kali VM2 | **phone hotspot IP** via USB tethering (record it before each run) |
| Attacker (alt.) | AWS CloudShell | AWS-owned IP (S2 rule tests) |
| Log collector | `wazuh-reader` | home IP (IP-pinned policy) |

Record the attacker's public IP at the start of every run: `curl -s https://checkip.amazonaws.com`.

## 4. Pre-run checklist
- [ ] `refresh_home_ip.ps1` done; `terraform.tfvars` `my_ips` correct.
- [ ] Stack applied, **≥ 5 minutes waited** (new-trail warm-up), `update_instance_ip.ps1` done, SNS subscription confirmed.
- [ ] Wazuh agent Active, trail reader `files=1+`, IAM poller running.
- [ ] Toggles set for the run (e.g. S1 detection run: `insecure_bucket=true`, `lambdas_enabled=false`; containment run: same toggle + `lambdas_enabled=true`).
- [ ] Budget OK (< $5 alert threshold), credits checked.
- [ ] Start time (UTC) and attacker IP written in the run log.

## 5. Stop conditions (stop immediately, revert, then investigate)
- Any action reaches something **out of scope** (wrong account, resource without `Project=seclab`).
- **Real** data or a **real** secret is exposed (anything other than the Faker file and lab credentials).
- AWS budget alert, unexpected charges, or any message from AWS (abuse report, security notice).
- Remediation loop: more than **10 SNS emails in 5 minutes** from the same Lambda → `aws events disable-rule` on all three rules.
- Unknown device appears in the Tailscale admin console.
- Laptop resources exhausted (VMs unstable) — evidence quality would suffer.

**Emergency revert:** `terraform apply` with all scenario toggles `false`; if in doubt, `terraform destroy`.

## 6. Evidence handling
- Raw evidence in `evidence/raw/<INC-id>/` (git-ignored, never pushed); only hashes and sanitized excerpts go into reports.
- Every evidence file hashed (SHA-256) at collection time; CloudTrail integrity proven with `aws cloudtrail validate-logs`.
- All timestamps in **UTC**; one timeline per scenario (`reports/timelines.xlsx`).
- Secrets never pasted into chats, tickets, screenshots or reports (masked input, key IDs only).

## 7. Communications
- Alerts: SNS email (Lambdas) and the Wazuh dashboard.
- Each run gets an ID (`INC-<yyyymmdd>-S<n>`) used in evidence folders, timelines and reports.

## 8. Approval
Approved by the account owner for the lab period. Any change to scope or techniques requires updating this document (new version) **before** the run.

| Version | Date | Change | Approved by |
|---|---|---|---|
| v1 | 2026-10-23 | Initial RoE for S1–S4 | Ziad Abbassi |
| v2 | 2026-10-23 | S4 (SSRF → stolen role credentials) removed from scope; no web app deployed; IMDSv1 kept as an L3 misconfiguration test only | Ziad Abbassi |
