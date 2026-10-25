# Note NOTE-20261024-MIMDS: IMDSv1 re-enabled on the web instance

| Field | Value |
|---|---|
| Type | Security event (misconfiguration), no attack |
| Severity | Low (corrected in seconds) |
| Status | Closed (2026-10-24 16:44 UTC) |
| Version | Public, sanitized |

**What happened.** `ModifyInstanceMetadataOptions` set `http_tokens = optional` on the web instance at **16:43:26 UTC** (Terraform toggle `imds_v1`). That re-allows **IMDSv1**, the metadata API version that answers simple GET requests. With IMDSv1, an SSRF bug in any web application on the instance would let an attacker read the instance role's temporary credentials.

**Response.** Lambda **L3** reset `http_tokens = required` (IMDSv2 only) at **16:43:32**, **6.4 s** later (SNS email, CloudTrail shows the call made by the L3 role). Wazuh rule **100132** raised the event at **16:44:49** (1 min 23 s after the change, 1 min 17 s after the fix).

**Why it matters.** IMDSv1 + SSRF is the root of several well-known cloud breaches. This scenario's full attack chain (SSRF → IMDSv1 → stolen role credentials, originally "S4") was taken out of scope on 2026-10-23. The misconfiguration test and the detection rules for stolen-credential use (100130/100131/100133) were kept.

**Actions.**
| # | Action | Risk | Status |
|---|---|---|---|
| 1 | Set the **account default** to IMDSv2 required (`ec2 modify-instance-metadata-defaults`) so new instances can't start with IMDSv1 | R05 | Phase 5 hardening |
| 2 | Keep hop limit 1 (credentials can't be reached from containers on the host) | R05 | Done |
| 3 | Keep L3 enabled | R05 | Done |

**Evidence (private):** `evidence/raw/INC-20261024-MIMDS/` (both `ModifyInstanceMetadataOptions` events, L3 log, SNS email, Wazuh alert, `SHA256SUMS.txt`).
