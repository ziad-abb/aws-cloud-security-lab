# Oracle Cloud (OCI) equivalents

How the same lab would be built on **Oracle Cloud Infrastructure**: the controls and scenarios carry over, the service names change. Useful for OCI-based employers and as proof that the design is not AWS-specific.

> Written from OCI documentation knowledge, not built and tested like the AWS lab. Check service limits and Free Tier availability before relying on a line.

## 1. Services
| Role in the lab | AWS (built) | OCI equivalent | Notes |
|---|---|---|---|
| Account boundary | Account (in an AWS-managed organization) | **Tenancy** + **compartments** | Compartments give finer isolation than one account per project |
| Organization guardrails | Service control policies | **IAM policies at tenancy level**, **Security Zones**, compartment quotas | Security Zones block insecure resources (e.g. public buckets) in a compartment |
| Network | VPC, public subnet, Internet Gateway | **VCN**, public subnet, Internet Gateway | Same model |
| Instance firewall | Security group | **Network Security Group (NSG)** or security list (stateful rules) | |
| Subnet firewall | Network ACL | **Security list** with stateless rules | |
| Flow logs | VPC flow logs | **VCN flow logs** (OCI Logging) | |
| Compute | EC2 t3.micro, Amazon Linux 2023 | **Compute instance** (e.g. Always Free Ampere A1 / E2.1.Micro), Oracle Linux | |
| Admin access without SSH | SSM Session Manager | **OCI Bastion** (managed, time-limited sessions) or Oracle Cloud Agent run command | Keeps port 22 closed to the internet |
| Instance metadata | IMDSv2 (session token) | **IMDS v2** endpoints; legacy v1 endpoints can be disabled per instance | Same SSRF protection idea |
| Instance identity | IAM role + instance profile | **Dynamic group** + policy (**instance principals**) | No credentials stored on the instance |
| Object storage | S3 bucket | **Object Storage bucket** | Bucket visibility "Private"; public access is a per-bucket setting |
| Block public storage | S3 Block Public Access (bucket + account) | Private bucket visibility + **Security Zone** recipe "deny public buckets" + Cloud Guard detector | |
| Encryption keys | KMS customer-managed key | **OCI Vault** master encryption key (rotation) | Bucket encrypted with a Vault key |
| Secrets | SSM Parameter Store SecureString | **OCI Vault secrets** | For the Tailscale auth key |
| API audit log | CloudTrail (management events) | **OCI Audit** (always on, 365-day retention, no setup) | IAM events are included: no us-east-1-style gap |
| Data access log | CloudTrail S3 data events | **Object Storage service logs** (read and write) in OCI Logging | |
| Log integrity | CloudTrail log-file validation | Audit logs are immutable; export to a bucket with **retention rules** | |
| Event routing | EventBridge | **OCI Events** rules | |
| Auto-remediation | Lambda | **OCI Functions** (Fn project) or **Cloud Guard responders** | Cloud Guard has built-in responders (e.g. make bucket private) |
| Notifications | SNS email | **OCI Notifications** topic, email subscription | |
| Log shipping queue | S3 → SQS notification | **Service Connector Hub** → Object Storage / **Streaming** / **Queue** | Same "deliver in order, read with a script" pattern |
| Managed threat detection | GuardDuty / Security Hub (not available on the plan) | **Cloud Guard** (detector + responder recipes), **Vulnerability Scanning** | Available in OCI tenancies |
| CIS posture scan | Prowler, CIS AWS 7.0 | **CIS OCI Foundations Benchmark**: Cloud Guard + Oracle's CIS compliance script, or Prowler / Steampipe OCI plugins | |
| Infrastructure as code | Terraform (AWS provider) | Terraform (**OCI provider**) or **OCI Resource Manager** (hosted Terraform) | |
| Long-lived credentials | IAM access keys (`AKIA…`) | **API signing keys**, **customer secret keys** (S3-compatible), **auth tokens** | All can leak like an AWS key |

## 2. Scenarios on OCI
| Lab scenario | OCI version | Detection | Containment |
|---|---|---|---|
| S1 public bucket | Bucket visibility changed to "Public" and an object read anonymously | Audit event `UpdateBucket` (public access type) + Object Storage read logs; Cloud Guard "bucket is public" detector | Cloud Guard responder or a Function sets the bucket back to private; Security Zone prevents it entirely |
| S2 leaked key | A user's API signing key or customer secret key committed to Git | Audit events from an unknown IP; new API key added (`UploadApiKey`) = persistence | Deactivate the user / remove the keys (`DeleteApiKey`), deny via group policy, hunt in Audit |
| S3 SSH open | NSG / security list rule TCP 22 from 0.0.0.0/0 + brute force | Audit `UpdateSecurityList` / NSG rule events; Cloud Guard "open port" detector; agent logs on the instance | Function or Cloud Guard responder removes the rule; Bastion as the only admin path |
| M-IMDS | Legacy IMDS v1 endpoints re-enabled | Audit `UpdateInstance` (instance options) | Function sets `areLegacyImdsEndpointsDisabled = true` |

## 3. What would be easier or harder
- **Easier:** Audit covers IAM events in every region (no poller needed); Cloud Guard gives managed detection and responders out of the box.
- **Harder:** Wazuh has no native OCI module (logs go through Service Connector Hub to a bucket or a stream, then a small reader script, as in this lab). OCI IAM policy language and compartments take time to learn.
