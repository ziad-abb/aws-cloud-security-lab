# Incident report INC-20261024-S2: Leaked CI access key with persistence

| Field | Value |
|---|---|
| Incident ID | INC-20261024-S2 |
| Type (ISO/IEC 27035) | Information security incident: unauthorized access using compromised credentials |
| Severity | **High** at detection, raised to **Critical** when persistence was confirmed (rule 100113, level 14) |
| Status | Closed (2026-10-24 16:42 UTC) |
| Handler | Ziad Abbassi (incident lead and responder) |
| Environment | AWS lab account (ID redacted), region eu-north-1, Wazuh 4.14 SIEM |
| Data involved | `clients-s3.csv`, **synthetic** customer records (Faker, 50 rows) |
| Runbook used | [`runbooks/leaked-key.md`](../../runbooks/leaked-key.md) (RB-S2) |
| Version | Public, sanitized: no IPs, access-key IDs shortened, account ID redacted |

> **Lab exercise.** The leak was planted on purpose and the attacker was played by the author under written [rules of engagement](../../runbooks/rules-of-engagement.md). Detection, response and measurements are real.

## 1. Summary
A long-lived access key of the CI user `dev-ci` was committed to a CI repository in a `.env` file and then "removed" in a later commit, which left it in the Git history. An attacker ran **TruffleHog** on the repository, found and verified the key, used it from an unknown mobile IP to list the data bucket and download a customer file, and **created a second access key** for persistence.

Wazuh raised the first alert **3 min 41 s** after the first malicious call and the persistence alert 3 min 40 s after the second key was created. The responder contained the user **2 min 42 s after the first alert** (6 min 23 s after the first malicious call) by attaching `AWSDenyAll`, then deactivated both keys, hunted for other persistence in us-east-1, collected and hashed evidence, deleted the keys and removed the leak. One synthetic customer file was disclosed. The KMS-encrypted copy stayed protected because `dev-ci` had no `kms:Decrypt` permission.

## 2. Timeline (UTC, 2026-10-24)
| Time | Source | Event | Phase (ISO 27035) |
|---|---|---|---|
| 16:29:31 | CloudTrail (us-east-1) | Access key `AKIA…UMR` created for `dev-ci` and committed to the CI repo (planted leak); rule 100111 (level 5, admin from a known IP) | — |
| **16:31:32** | CloudTrail | TruffleHog verifies the key with `sts:GetCallerIdentity` from the attacker IP: **first malicious call (T0)** | — |
| 16:32:16 | CloudTrail | `GetCallerIdentity` (attacker confirms the identity `user/dev-ci`) | — |
| ~16:32:20 | CloudTrail | `ListObjectsV2` on the data bucket, then `GetObject clients-s3.csv`: **success (data disclosed)** | — |
| ~16:32:25 | CloudTrail | `GetObject clients-kms.csv`: **AccessDenied** (`kms:Decrypt` not allowed) | — |
| 16:32:34 | CloudTrail (us-east-1) | `CreateAccessKey`: second key `AKIA…XGS` created by the leaked key: **persistence** | — |
| **16:35:13** | Wazuh | **100110** (level 12): dev-ci key used from an unknown IP (`GetCallerIdentity`) | Detect and report |
| 16:36:13 | Wazuh (IAM poller) | **100113** (level 14): leaked key created a new access key | Detect and report |
| 16:37:30 | Responder | Key list reviewed: 2 keys, one not created by the owner → persistence confirmed, severity Critical | Assess and decide |
| **16:37:55** | Responder | `AWSDenyAll` attached to `dev-ci` (blocks every key, known or not): **contained** | Respond: contain |
| 16:38:10 | Responder | Both keys set to Inactive | Respond: contain |
| 16:38:20 | Responder | Hunt in us-east-1 by user name: only `GetCallerIdentity` + `CreateAccessKey` (an older `CreateAccessKey` from 2026-10-23 belonged to an earlier test user with the same name, see §8) | Respond: contain |
| 16:38:32 | Attacker view | Leaked key → `InvalidClientTokenId` (STS), `InvalidAccessKeyId` (S3) | Containment verified |
| 16:39–16:41 | Responder | Evidence collected (event history in both regions by key ID, trail data events, Wazuh alerts) and hashed (SHA-256) | Respond: evidence |
| 16:42 | Responder | Both keys deleted, leak repository and bundle deleted, attacker-side files removed, `AWSDenyAll` detached (user back to baseline: least-privilege policy, no key) | Eradicate and recover |
| 16:46 | Responder | `validate-logs`: 1/1 digest, 17/17 log files valid for 15:35–16:34 (covers every attacker action) | Evidence integrity |

## 3. Detection and reporting
| Signal | Pipeline | Latency |
|---|---|---|
| 100110: dev-ci key from an IP not in `seclab-known-ips` | CloudTrail → S3 → SQS → trail reader → Wazuh | **3 min 41 s** after T0 |
| 100113: persistence (leaked key creates a key) | us-east-1 event history → IAM poller → Wazuh | 3 min 40 s after `CreateAccessKey` |
| 100111: key created by the admin (planting step) | IAM poller | ~2.5 min (low level: known admin, known IP) |

Detection worked because the rules key on **identity + source IP** (the CI user should only be used from known CI addresses). The persistence detection only exists because of the **IAM poller**: IAM is a global service logged in us-east-1, and the lab's regional trail never receives `CreateAccessKey`.

## 4. Assessment and decision
- **Is it the leaked key?** Yes: the key ID in alert 100110 matched the key exposed in the repo.
- **Is the source legitimate?** No: a mobile-carrier IP, not a known CI or admin IP.
- **Is there persistence?** Yes: `list-access-keys` showed a second key that the owner did not create.
- **Decision:** contain immediately. Containment is reversible (deny + deactivate, nothing deleted), so a false positive would cost only minutes of CI downtime.

## 5. Response
**Containment (RB-S2 §4.1–4.3).** `AWSDenyAll` was attached **first**, because it blocks every key of the user, including attacker-created keys not yet found. Then both keys were deactivated (kept as evidence), and the us-east-1 event history was searched for other persistence (`CreateUser`, `CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, keys for other users): none found. The attacker's next calls failed.

**Evidence (RB-S2 §4.4).** Event history by access-key ID for both keys in both regions, the CloudTrail files for the day (S3 data events are not in the event history), the Wazuh alerts for both key IDs (10 alerts) and the CloudTrail digest validation. Every file is hashed in `SHA256SUMS.txt`. The raw evidence is kept privately (it contains the real account ID and IPs) and is not published.

**Eradication and recovery (RB-S2 §4.5–4.6).** Both keys were deleted, and the leaking repository and its bundle were destroyed. In a real company the secret would also be removed from every copy of the repo, but **a key is burnt the moment it is public**: rewriting history does not "un-leak" it, so rotation is mandatory. `AWSDenyAll` was detached once no key existed; CI keeps no standing key between runs.

## 6. Impact
| Item | Result |
|---|---|
| Data disclosed | `clients-s3.csv` (synthetic PII, 50 rows), 1 download |
| Data protected | `clients-kms.csv`: denied (no `kms:Decrypt`), defence in depth through encryption + least privilege |
| Privileges obtained | Only `dev-ci`'s own rights (list/read the data bucket, manage its own keys). No privilege escalation was possible |
| Persistence | 1 extra access key; neutralized 5 min 21 s after creation |
| Window of unauthorized access | 16:31:32 → 16:37:55 = **6 min 23 s** |
| Other systems | None (no other identity or resource touched, confirmed by the hunt) |

In a real company this would be a personal-data breach, so the regulatory questions apply (see [law 09-08 note](../grc/law-09-08-note.md)).

## 7. Root cause
1. A **long-lived access key** existed for CI at all (instead of short-lived federated credentials).
2. The key was stored in a **file inside the repository** and "deleted" with a new commit, which leaves it in history.
3. No **secret scanning** blocked the commit (no pre-commit hook, no push protection).
4. The key could **create more keys** (self-service rotation), which turned a leak into persistence.

## 8. Lessons learned and actions
| # | Action | Type | Risk | Status |
|---|---|---|---|---|
| 1 | Replace CI keys with **OIDC federation** (GitHub Actions → IAM role, credentials valid for minutes) | Preventive | R02 | Recommended (out of lab scope) |
| 2 | Secret scanning: TruffleHog/gitleaks pre-commit + GitHub push protection | Preventive | R02 | Done on this repo (TruffleHog scans before publishing) |
| 3 | Remove `iam:CreateAccessKey` from CI identities; rotation done by an admin process | Preventive | R03 | Recommended |
| 4 | Keep 100113 at level 14 and page on it: persistence is the strongest signal | Detective | R03 | Done |
| 5 | Investigate by **principal ID**, not user name: a name-based hunt returned an event from an older user with the same name (2026-10-23) | Procedure | — | Added to RB-S2 |
| 6 | Treat access-key IDs as sensitive in published reports: they can be decoded to the account ID | Procedure | R15 | Done (sanitization rule) |

## 9. Metrics
| Metric | Value |
|---|---|
| Time to detect (T0 → first alert) | **3 min 41 s** |
| Time to detect persistence | 3 min 40 s |
| Time to contain after the alert (manual) | **2 min 42 s** |
| Time to contain from T0 | **6 min 23 s** |
| Time to eradicate (T0 → keys deleted) | ~10.5 min |

## 10. MITRE ATT&CK
| Tactic | Technique | Observed |
|---|---|---|
| Credential Access | T1552.001 Unsecured Credentials: Credentials in Files | Key in `.env` in Git history, found by TruffleHog |
| Initial Access / Defense Evasion | T1078.004 Valid Accounts: Cloud Accounts | Leaked key used from the attacker IP |
| Discovery | T1087.004 Account Discovery: Cloud Account | `sts:GetCallerIdentity` |
| Discovery | T1619 Cloud Storage Object Discovery | `ListObjectsV2` on the data bucket |
| Collection | T1530 Data from Cloud Storage | `GetObject clients-s3.csv` |
| Persistence | T1098.001 Account Manipulation: Additional Cloud Credentials | `CreateAccessKey` |

## 11. Evidence register (private, not published)
| Item | Location | Integrity |
|---|---|---|
| Event history by key ID (eu-north-1 + us-east-1, both keys) | `evidence/raw/INC-20261024-S2/events-*.json` | SHA-256 in `SHA256SUMS.txt` |
| CloudTrail files of the day + data events by key | `.../trail/`, `.../data-events-by-key.txt` | SHA-256 + CloudTrail digest validation (1/1, 17/17 valid) |
| Wazuh alerts for both keys (10) | `.../inc-s2-alerts.json` | SHA-256 |
| Run log | `reports/timelines.xlsx` (sanitized, public) | — |

## 12. Limitations
- Planted leak and a known attacker; real leaks are often found by automated bots within minutes of a public push. That's why the lab never pushed the key to GitHub.
- Detection relies on a list of known IPs. A real CI system with changing egress IPs would need a different baseline (e.g. allow-list the CI provider's ranges, alert on new ASNs).
- Detection time (~3.5 min) is bounded by CloudTrail delivery. The persistence was blocked within minutes, but the data download (seconds after T0) could not be prevented by detection alone. Prevention (OIDC, no standing keys) is the real fix.
