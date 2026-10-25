# Incident report INC-20261024-S3: SSH exposed to the internet and brute-force attempt

| Field | Value |
|---|---|
| Incident ID | INC-20261024-S3 (runs S3a, S3b) |
| Type (ISO/IEC 27035) | Information security event escalated to incident: exposure of an administrative service + attack attempt |
| Severity | **Medium** (service exposed and attacked; no access gained) |
| Status | Closed (2026-10-24 16:00 UTC) |
| Handler | Ziad Abbassi |
| Environment | AWS lab account (ID redacted), eu-north-1, EC2 Amazon Linux 2023 with Wazuh agent, Lambda L2 |
| Version | Public, sanitized |

> **Lab exercise.** Port 22 was opened on purpose with the Terraform toggle `ssh_open`, and the attack came from the author's Kali VM on a mobile IP, within the [rules of engagement](../../runbooks/rules-of-engagement.md) (≤ 200 attempts, ≤ 5 min).

## 1. Summary
A security-group rule allowed TCP 22 from `0.0.0.0/0` to the web instance, which normally has **no inbound rules at all** (administration is through SSM Session Manager only). The attacker tried a password brute force: **Hydra aborted immediately because the server accepts no password authentication**. A username sweep then produced 41 failed logins. No login succeeded.
- **S3a (automation off):** the agent detected the failed logins in **seconds**, CloudTrail-based detection of the exposure took **4 min 46 s**, and manual containment took **7 min 57 s**.
- **S3b (automation on):** Lambda **L2** removed the rule **5.3 s** after it was created. The attacker's first connection attempt already timed out.

## 2. Timeline (UTC, 2026-10-24)
| Time | Run | Source | Event |
|---|---|---|---|
| **15:44:53** | S3a | CloudTrail | `AuthorizeSecurityGroupIngress` tcp/22 from 0.0.0.0/0: **T0** |
| 15:45:15 | S3a | Attacker | Hydra (50 users × 4 passwords): aborted, "does not support password authentication" |
| 15:46:20–15:47:40 | S3a | Attacker | Username sweep (first pass discarded: it left through the home IP because of a VM routing issue) |
| 15:47:03 | S3a | Wazuh agent | **5710** attempt with a non-existent user (first alert) |
| 15:49:39 | S3a | Wazuh | **100121** (level 13) SSH opened to the internet |
| ~15:50:00–15:51:07 | S3a | Attacker | Username sweep from the mobile IP: 41 attempts |
| 15:50:27 | S3a | Wazuh agent | **5712** (level 10) brute force with non-existent users |
| **15:52:50** | S3a | Responder | Rule revoked (Terraform): **contained** |
| **15:57:35** | S3b | CloudTrail | Same rule created again: **T0** |
| **15:57:40** | S3b | Lambda L2 | Every internet-open ingress rule revoked, SNS email, `seconds_from_change_to_fix = 5.3`: **contained** |
| 15:58:18–15:59:08 | S3b | Attacker | 6 attempts, all "connection timed out" |
| 16:00:12 | S3b | Wazuh | 100121 for S3b: arrives 2 min 32 s **after** containment |

## 3. Detection
| Signal | Pipeline | Latency |
|---|---|---|
| 5710 / 5712 sshd failures | Wazuh agent on the instance (journald) over Tailscale | **seconds** (~40 s after the first attempt, including the sweep's own pace) |
| 100121 SG open to the internet | CloudTrail → SQS → Wazuh | 4 min 46 s (S3a), 2 min 37 s (S3b) |

Host telemetry is much faster than the cloud control-plane path. The two complement each other: one sees the exposure, the other sees the attack.

The rule 5715 "authentication success" alerts seen the same day came from host `wazuh-srv` (the author's own SSH logins to the SIEM VM), **not** from the cloud instance. They were checked and closed as benign.

## 4. Response
- **S3a:** the rule was revoked by Terraform 7 min 57 s after T0.
- **S3b:** L2 checks that the group carries the lab tag, reads the **current** rules (not just the event) and revokes every ingress rule open to `0.0.0.0/0` or `::/0`. Its IAM role can only revoke on groups tagged `Project=seclab`. Terraform later noticed the rule was gone and removed it from its state.

## 5. Impact
No successful authentication, no session, no change on the host. The exposure lasted 7 min 57 s (S3a) and 5.3 s (S3b).

## 6. Root cause
- **Direct cause:** a security-group rule open to the internet on an administrative port (the deliberate misconfiguration).
- **Why the attack failed anyway:** the instance has no key pair, no passwords and SSH is not used at all (SSM only). That is a **compensating control** that made the exposure low-impact.

## 7. Lessons learned and actions
| # | Action | Type | Risk | Status |
|---|---|---|---|---|
| 1 | Restrictive **network ACL** on the subnet (second layer: blocks 22/3389 even if a security group is opened) | Preventive | R04 | Phase 5 hardening |
| 2 | Keep administration on SSM only; no key pair, no password authentication | Preventive | R04 | Done (proven: Hydra aborted) |
| 3 | Keep L2 always enabled; it also removed an older forgotten open rule during testing because it reads the current state | Corrective | R04 | Done |
| 4 | Correlate 100121 with 57xx from the same instance to raise one high-severity incident ("exposed and attacked") | Detective | R04 | Recommended |
| 5 | VPC flow logs to see connection attempts that never reach sshd | Detective | R04 | Phase 5 hardening |

## 8. Metrics
| Run | First alert | Exposure detected | Time to contain |
|---|---|---|---|
| S3a (manual) | 15:47:03 (agent, 2 min 10 s after T0, ~40 s after the first attempt) | 4 min 46 s | **7 min 57 s** |
| S3b (L2) | 2 min 37 s (after containment) | 2 min 37 s | **5.3 s** |

## 9. MITRE ATT&CK
| Technique | Observed |
|---|---|
| T1562.007 Impair Defenses: Disable or Modify Cloud Firewall | Security group opened to 0.0.0.0/0 (here a mistake, but the same change an attacker would make) |
| T1110.001 Brute Force: Password Guessing | Hydra (aborted) |
| T1110 Brute Force (user enumeration) | 41 attempts with non-existent users |

## 10. Evidence register (private)
`evidence/raw/INC-20261024-S3a/` and `.../INC-20261024-S3b/`: `AuthorizeSecurityGroupIngress` / `RevokeSecurityGroupIngress` events, Wazuh alerts (87 for S3a, including the discarded pass), L2 Lambda log, SNS email, `SHA256SUMS.txt`. CloudTrail digest validation: 1/1, 17/17 valid.
