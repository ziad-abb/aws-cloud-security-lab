# Prowler summary: CIS AWS Foundations 7.0 (sanitized)

Three scans of the same lab account with Prowler 5.x (`prowler aws --compliance cis_7.0_aws`). Raw reports stay private (they contain account and resource IDs).

## Scores (Prowler's official CIS 7.0 compliance result)
| Scan | When | State of the account | CIS 7.0 | Pass | Fail |
|---|---|---|---|---|---|
| #1 baseline | 2026-10-21 | Secure baseline stack (network, IAM, S3 + KMS, CloudTrail, EC2, SNS) | **53.33 %** | 40 | 35 |
| #2 during | 2026-10-24 16:09 UTC | Full stack + detection + Lambdas, **data bucket public** (scenario S1a) | **57.14 %** | 52 | 39 |
| #3 after | 2026-10-25 01:20 UTC | Full stack + Phase 5 hardening | **67.71 %** | 65 | 31 |

**Why #2 is higher than #1 although a bucket was public:** the stack had grown (Lambdas, SQS, EventBridge, extra KMS key), which added passing checks. A percentage hides a new critical failure; read the per-requirement changes below.

## Requirements fixed by the hardening (#2 → #3)
| CIS 7.0 | Requirement | Fix |
|---|---|---|
| 2.8 | IAM password policy requires a minimum length of 14 or greater | `aws_iam_account_password_policy` |
| 2.9 | IAM password policy prevents password reuse | same (reuse 24) |
| 2.15 | A support role has been created to manage incidents with AWS Support | `seclab-support` role with `AWSSupportAccess` |
| 3.1.4 | S3 is configured with Block Public Access enabled (account level) | `aws_s3_account_public_access_block` |
| 4.4 | Server access logging is enabled on the CloudTrail S3 bucket | `aws_s3_bucket_logging` → log bucket |
| 4.7 | VPC flow logging is enabled in all VPCs | `aws_flow_log` (ALL traffic) + default VPC deleted |

No requirement went from pass to fail. Other hardening (network ACL, IMDSv2 account default, default VPC deletion) reduced EC2 failures from 6 to 4.

## Failed findings by service
| Service | #2 during | #3 after |
|---|---|---|
| cloudtrail | 19 | 18 |
| iam | 8 | 5 |
| ec2 | 6 | 4 |
| s3 | 4 | 3 |
| config | 1 | 1 |
| vpc | 1 | 0 |

## Remaining failures (31) and why
| Group | Treatment |
|---|---|
| 16 CloudWatch metric-filter / alarm checks (CIS monitoring of CloudTrail events) | **Compensated:** the same events are detected by custom Wazuh rules (see `reports/grc/control-mapping.md` §2) |
| Multi-region trail | **Accepted:** the account type supports a single region only (risk R09) |
| AWS Config not enabled | **Accepted:** not available / cost (risk R14) |
| Policies attached directly to IAM users | **Accepted:** an AWS-managed service control policy on this account type **denies IAM group operations**, so "permissions through groups" cannot be implemented (risk R10) |
| MFA Delete on buckets, root credential management | **Accepted:** need root via CLI / AWS Organizations management access |
| Remaining EC2 / S3 items (e.g. object-level logging scope, NACL details) | Reviewed; to be detailed from the raw report if needed |

> Note: the baseline scan (#1) was taken with an earlier Prowler build whose CIS 7.0 mapping grouped the CloudWatch alarm checks under section 5 (Monitoring); later scans list them under section 4 (Logging). Section-level counts are therefore only comparable between #2 and #3.
