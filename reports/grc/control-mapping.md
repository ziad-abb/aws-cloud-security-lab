# Control mapping: lab controls → CIS AWS 7.0 · ISO/IEC 27001:2022 · ISO/IEC 27017 · NIST CSF 2.0

Each control below exists in this repository and was **tested** on 2026-10-24 (see `reports/incidents/`). CIS references are given at **section** level (the exact requirement IDs are listed in the Prowler compliance CSV for CIS AWS 7.0). ISO/IEC 27017 references are the cloud-specific controls (CLD.x) and the cloud guidance it adds to ISO/IEC 27002.

## 1. Mapping table
| # | Control in the lab | Where | Type | CIS AWS 7.0 | ISO 27001:2022 Annex A | ISO 27017 | NIST CSF 2.0 | Tested / evidence |
|---|---|---|---|---|---|---|---|---|
| C01 | S3 Block Public Access on the data and trail buckets | `terraform/s3.tf`, `cloudtrail.tf` | Preventive | §3 Storage | 8.3, 8.12 | 9.4.1 + CLD.6.3.1 (shared responsibility) | PR.DS-01, PR.AA-05 | S1: public only when deliberately disabled |
| C02 | TLS-only bucket policy (`aws:SecureTransport`) | `s3.tf` | Preventive | §3 Storage | 8.24 | 10.1.1 | PR.DS-02 | Prowler pass |
| C03 | Customer-managed KMS key for sensitive objects, rotation on | `kms.tf` | Preventive | §3 Storage | 8.24, 5.33 | 10.1.1, 10.1.2 | PR.DS-01 | S1/S2: KMS copy never readable by the anonymous user or the leaked key |
| C04 | Least-privilege IAM: one role per Lambda (resource/tag-scoped), app role read-only, CI user without `kms:Decrypt` | `iam.tf`, `lambda.tf`, `iam/*.json` | Preventive | §2 IAM | 5.15, 5.18, 8.2 | 9.2.3, 9.4.1 | PR.AA-05 | S2: attacker limited to one file |
| C05 | No SSH, no key pair: admin through SSM Session Manager only | `ec2.tf`, `network.tf` | Preventive | §6 Networking | 8.5, 8.20 | CLD.12.1.5 (admin operational security) | PR.AA-03, PR.IR-01 | S3: Hydra aborted, 0 logins |
| C06 | Security group with no inbound rule; default SG locked | `network.tf` | Preventive | §6 Networking | 8.20, 8.22 | CLD.9.5.1, 13.1.3 | PR.IR-01 | Prowler pass (lab VPC) |
| C07 | IMDSv2 required, hop limit 1 | `ec2.tf` | Preventive | §6 Networking (EC2) | 8.9 | CLD.9.5.2 (VM hardening) | PR.PS-01 | M-IMDS |
| C08 | EBS encryption by default | `ec2.tf` | Preventive | §6 Networking (EC2) / §3 | 8.24 | 10.1.1 | PR.DS-01 | Prowler pass |
| C09 | CloudTrail with S3 data events, log-file validation, KMS-encrypted trail bucket, 30-day lifecycle | `cloudtrail.tf` | Detective | §4 Logging | 8.15, 5.28 | 12.4.1, 12.4.2, CLD.12.4.5 | DE.CM-01, DE.CM-09 | `validate-logs`: 1/1 digest, 17/17 files valid |
| C10 | Ordered log ingestion (S3 → SQS → reader, DLQ) | `sqs.tf`, `wazuh/trail_sqs_reader.py` | Detective | §4 Logging | 8.15, 8.16 | 12.4.1 | DE.CM-01 | 26/26 anonymous reads ingested |
| C11 | us-east-1 IAM event poller (global-service gap) | `wazuh/iam_poller.py` | Detective | §4 Logging | 8.15, 8.16 | 12.4.1 | DE.CM-01 | S2: 100113 persistence alert |
| C12 | 21 custom Wazuh rules (S3 exposure, key misuse, persistence, SG exposure, IMDS, tampering, KMS) | `wazuh/local_rules.xml` | Detective | §5 Monitoring (replaces the CloudWatch metric-filter/alarm checks) | 8.16, 5.25 | 12.4.1, CLD.12.4.5 | DE.CM-09, DE.AE-02 | Every scenario detected |
| C13 | Host agent on the instance (sshd via journald) over Tailscale | `user_data.sh.tftpl` | Detective | — | 8.16 | 12.4.1 | DE.CM-09 | S3: 5710 in seconds |
| C14 | Auto-remediation L1 (S3 re-block), L2 (SG revoke), L3 (IMDSv2), with loop guards, SNS report and containment metric | `lambda/`, `lambda.tf` | Corrective | §3 / §6 | 5.26, 8.9 | 16.1.5 | RS.MI-01, RS.MI-02 | 9.9 s / 5.3 s / 6.4 s |
| C15 | Incident runbook (ISO 27035 phases), evidence collection and SHA-256 hashing | `runbooks/leaked-key.md` | Corrective / procedural | — | 5.24, 5.26, 5.28 | 16.1.5, 16.1.7 | RS.MA-01, RS.AN-03, RS.MI-01 | S2: contained 2 min 42 s after the alert |
| C16 | Rules of engagement for testing | `runbooks/rules-of-engagement.md` | Procedural | — | 5.8, 8.29 (security testing) | 14.2.8 | ID.IM-02 | All runs within limits |
| C17 | Lessons learned, risk register | `reports/` | Procedural | — | 5.27, 6.8 (event reporting) | 16.1.6 | ID.IM-03, GV.RM | This package |
| C18 | Infrastructure as code with toggles, LocalStack tests, destroy after every session | `terraform/` | Preventive | — | 8.9, 8.32, 8.25 | 12.1.2, CLD.12.1.5 | PR.PS-01, ID.AM-08 | 60-resource stack rebuilt identically each session |
| C19 | Secrets never in code or Terraform state; secret scanning before publishing | `.gitignore`, procedure | Preventive | §2 IAM | 5.17, 8.4, 8.12 | 9.4.3 | PR.AA-01, PR.DS-01 | Fresh-clone TruffleHog scan: 0 secrets |
| C20 | Synthetic data only (Faker) | `scripts/gen_fake_data.py` | Preventive | — | 5.34, 8.33 (test information) | 18.1.4 | GV.OC-03 | — |
| C21 | Budget alert, cost rules | account | Governance | — | 5.37 (documented operating procedures) | — | GV.RR | No cost surprise |

## 2. CIS CloudWatch alarm checks compensated by Wazuh
CIS AWS section 5 (Monitoring) expects CloudWatch metric filters and alarms on CloudTrail. The lab has no CloudWatch alarm pipeline; the same events are detected in Wazuh instead. Prowler reports these checks as FAIL, so they are documented here as **compensating controls**.

| CIS monitoring topic | Wazuh rule(s) |
|---|---|
| CloudTrail configuration changes | 100140 |
| S3 bucket policy changes | 100102 (+ 100100/100101 for BPA) |
| Security group changes | 100120, 100121 |
| Disabling or scheduled deletion of KMS keys | 100142 |
| IAM policy changes / access keys | 100111, 100112, 100113 |
| Unauthorized or anonymous API calls | 100103, 100104, 100110, 100150 |
| Console sign-in without MFA / root usage | Not covered (no IAM console users; root not used). Gap accepted |
| NACL / route table / VPC / network gateway changes | Not covered yet. Gap: add rules in Phase 5 |
| AWS Config changes | Not applicable (Config not available on the plan) |

## 3. Known gaps (mapped to the risk register)
| Gap | Framework reference | Risk |
|---|---|---|
| Single-region trail, no multi-region coverage | CIS §4, ISO 8.15 | R09 |
| No AWS Config / GuardDuty / Security Hub | CIS §4/§5, ISO 5.7, 8.16 | R14 |
| Admin permissions attached to a user, not a group | CIS §2, ISO 5.15, 8.2 | R10 |
| No account-level S3 BPA, no NACL, no flow logs, no access logging on the trail bucket (until Phase 5 hardening) | CIS §3/§4/§6, ISO 8.15, 8.20 | R01, R04 |
| No rules yet for network-change events (NACL, routes, gateways) | CIS §5, ISO 8.16 | R04 |
