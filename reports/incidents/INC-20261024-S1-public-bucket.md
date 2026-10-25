# Incident report INC-20261024-S1: Public S3 bucket and anonymous data access

| Field | Value |
|---|---|
| Incident ID | INC-20261024-S1 (runs S1a, S1b-1, S1b-2) |
| Type (ISO/IEC 27035) | Information security incident: data exposure through misconfiguration |
| Severity | **High** (personal data readable by anyone on the internet) |
| Status | Closed (2026-10-24 16:27 UTC) |
| Handler | Ziad Abbassi |
| Environment | AWS lab account (ID redacted), eu-north-1, Wazuh 4.14, Lambda L1 |
| Data involved | `clients-s3.csv` (SSE-S3) and `clients-kms.csv` (SSE-KMS), **synthetic** customer records |
| Version | Public, sanitized |

> **Lab exercise.** The misconfiguration was applied on purpose with the Terraform toggle `insecure_bucket`; the "attacker" was the author with plain `curl`, under the [rules of engagement](../../runbooks/rules-of-engagement.md).

## 1. Summary
The data bucket's Block Public Access (BPA) settings were turned off and a bucket policy allowing `s3:GetObject` to everyone was applied. An anonymous user then downloaded the SSE-S3 customer file. The SSE-KMS copy could not be read anonymously.

The scenario was run three times:
- **S1a (automation off):** Wazuh detected the change in ~3 min and the anonymous read 3 min 34 s after it happened. Manual containment took **~8 min**.
- **S1b-1 (automation "on" but not armed):** the EventBridge rule had been enabled only **40 s** before the change and matched nothing, so the Lambda never ran. **Wazuh still detected the anonymous reads ~1 min after the first one.** The bucket stayed public for 6 min 25 s.
- **S1b-2 (automation armed):** Lambda **L1** re-enabled BPA **9.9 s** after the change; the attacker saw `403` from the next request.

## 2. Timeline (UTC, 2026-10-24)
| Time | Run | Source | Event |
|---|---|---|---|
| **16:07:32** | S1a | CloudTrail | `PutBucketPublicAccessBlock` (all false) + `PutBucketPolicy` (public read): **T0** |
| 16:08:14 | S1a | CloudTrail (data event) | Anonymous `GetObject clients-s3.csv` → **200 (data disclosed)** |
| 16:08:19 | S1a | CloudTrail (data event) | Anonymous `GetObject clients-kms.csv` → **400** (KMS objects need an authenticated, signed request) |
| 16:09:01 | S1a | Prowler | CIS scan #2 started while the bucket was public |
| 16:10:44 | S1a | Wazuh | **100101** BPA disabled (level 10), **100102** public bucket policy (level 12) |
| 16:11:48 | S1a | Wazuh | **100103** anonymous read (level 12), **100104** anonymous read denied (level 7) |
| **16:15:27** | S1a | Responder | BPA re-enabled and policy reverted (Terraform): **contained** |
| 16:18:19 | S1b | CloudTrail | `PutRule` ×3: remediation rules enabled |
| **16:18:59** | S1b-1 | CloudTrail | BPA off + public policy: **T0**. EventBridge: **no match, L1 not invoked** |
| 16:19:05–16:19:34 | S1b-1 | Attacker | 20 anonymous reads, all **200** |
| 16:20:16 | S1b-1 | Wazuh | **100103** for the anonymous reads: detected without automation |
| 16:21 | S1b-1 | Responder | Diagnosis: rule `ENABLED`, no Lambda log, no EventBridge metric datapoint → event never matched |
| **16:25:14** | S1b-2 | CloudTrail | BPA set off again (fresh trigger): **T0** |
| 16:25:20–16:25:23 | S1b-2 | Attacker | 3 anonymous reads → 200 |
| **16:25:23.9** | S1b-2 | Lambda L1 | BPA re-enabled (all 4 flags), SNS email, `seconds_from_change_to_fix = 9.9`: **contained** |
| 16:25:24 → | S1b-2 | Attacker | Every request → **403** |
| 16:26:43 | S1b-2 | Wazuh | 100103 (last successful reads) + 15 × 100104 (blocked reads) |
| ~16:27 | S1b | Responder | Leftover public policy statement removed (Terraform); evidence hashed |

## 3. Detection
| Signal | Latency |
|---|---|
| 100101/100102 (configuration change) | ~3 min 12 s (S1a) |
| 100103 (anonymous read, S3 data event) | 3 min 34 s (S1a), ~1 min 11 s (S1b-1) |
| 100104 (anonymous read denied) | ~1–3.5 min |

Rule 100103 keys on `userIdentity.type = AWSAccount` with `accountId = anonymous` in S3 data events. It **had never fired on real traffic before this incident**. During Phase 2 the stock Wazuh S3 reader silently skipped late-arriving data-event files; the SQS-based reader built to fix that delivered every read in this incident (26 × 100103).

## 4. Response
- **S1a (manual):** BPA re-enabled and the public statement removed with Terraform (`insecure_bucket = false`), 7 min 55 s after T0.
- **S1b-1:** the rule was enabled but not effective yet. **Root cause: EventBridge rule changes are eventually consistent.** The responder confirmed with CloudWatch `AWS/Events` metrics (no `MatchedEvents`, no `TriggeredRules`) that the event had never matched, then re-triggered the change once the rule had been active for several minutes.
- **S1b-2 (automated):** L1 re-enabled all four BPA flags in 9.9 s. L1 does not remove the public policy, but with `BlockPublicPolicy` and `RestrictPublicBuckets` on, AWS ignores it, which is why access stopped immediately. The statement was removed afterwards by Terraform.

## 5. Impact
| Run | Exposure window | Successful anonymous reads | Blocked reads |
|---|---|---|---|
| S1a | 16:07:32 → 16:15:27 (7 min 55 s) | 1 (`clients-s3.csv`) | 1 (`clients-kms.csv`, KMS) |
| S1b-1 + S1b-2 | 16:18:59 → 16:25:24 (6 min 25 s) | ~25 | 15 after the fix |
| **Total** | ~14 min 20 s | **26** (Wazuh 100103 count) | 16 |

The SSE-KMS copy was never readable anonymously. Encryption with a customer-managed key adds an authorization step that a bucket policy alone cannot open.

## 6. Root cause
- **Direct cause:** BPA disabled + a public bucket policy (the deliberate misconfiguration).
- **Why it was possible:** no **account-level** BPA (it would have blocked the bucket-level change entirely). The account plan has no AWS Organizations, so SCPs are not available as a guardrail.
- **S1b-1 extra cause:** the remediation rule was switched on 40 s before the change. In production remediation rules stay on, so the equivalent risk is "automation silently not working".

## 7. Lessons learned and actions
| # | Action | Type | Risk | Status |
|---|---|---|---|---|
| 1 | Enable **account-level S3 Block Public Access** (preventive, stops S1 at the source) | Preventive | R01 | Phase 5 hardening |
| 2 | Keep remediation rules always enabled; after any change, wait ≥ 60 s and run a canary test | Procedure | R06 | Done (session checklist) |
| 3 | Alert when a 100101 is not followed by an L1 confirmation within 2 min ("automation did not fire") | Detective | R06 | Recommended |
| 4 | Keep sensitive objects SSE-KMS with a key policy limited to the application role | Preventive | R01 | Done (proven effective) |
| 5 | L1 should also delete the public policy statement, not only re-block | Corrective | R01 | Recommended |

## 8. Metrics
| Run | Time to detect (config) | Time to detect (data read) | Time to contain |
|---|---|---|---|
| S1a (manual) | ~3 min 12 s | 3 min 34 s | **7 min 55 s** |
| S1b-1 (not armed) | — | ~1 min 11 s | 6 min 25 s (by the S1b-2 retry) |
| S1b-2 (L1) | — | 1 min 29 s | **9.9 s** |

## 9. MITRE ATT&CK
| Technique | Observed |
|---|---|
| T1530 Data from Cloud Storage | Anonymous `GetObject` of the customer file |
| T1619 Cloud Storage Object Discovery | (possible for an attacker; a bucket listing was not allowed anonymously) |

## 10. Evidence register (private)
`evidence/raw/INC-20261024-S1a/` and `.../INC-20261024-S1b/`: `PutBucketPublicAccessBlock` / `PutBucketPolicy` / `PutRule` events, CloudTrail files of the day, anonymous data events by source IP, Wazuh alerts (4 + 41), L1 Lambda log, SNS email; each with `SHA256SUMS.txt`. CloudTrail digest validation: 1/1, 17/17 valid. Prowler #2 raw report kept private; sanitized summary in `reports/prowler/`.
