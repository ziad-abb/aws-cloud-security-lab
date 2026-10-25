# Phase 5 - final hardening (fixes from Prowler #1/#2 and the incident reports).
# Everything here is OFF by default: enable with  -var="hardening=true".
# Account-level guardrails (S3 BPA, password policy, IMDS defaults) are meant to STAY after the lab:
# before `terraform destroy`, remove them from state (see runbooks/phase5-hardening.md).
# Cost: log bucket + flow logs to S3 = cents for a 1-hour session; NACL, password policy, BPA, IMDS defaults, role = free.

variable "hardening" {
  description = "Phase 5: account BPA, password policy, IMDSv2 default, NACL, VPC flow logs, trail-bucket access logging, support role"
  type        = bool
  default     = false
}

locals {
  log_bucket = "${var.project}-logs-${local.account_id}"
}

# ---------- R01: account-level S3 Block Public Access (stops S1 at the source) ----------
# Skipped while insecure_bucket=true, otherwise S1 could not be reproduced.
resource "aws_s3_account_public_access_block" "this" {
  count                   = var.hardening && !var.insecure_bucket ? 1 : 0
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# ---------- CIS IAM: password policy (14 chars, reuse 24) ----------
resource "aws_iam_account_password_policy" "this" {
  count                          = var.hardening ? 1 : 0
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

# ---------- R05: IMDSv2 required by default for every new instance in the region ----------
resource "aws_ec2_instance_metadata_defaults" "this" {
  count                       = var.hardening ? 1 : 0
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
  http_endpoint               = "enabled"
  instance_metadata_tags      = "disabled"
}

# ---------- CIS IAM: support role (AWSSupportAccess) ----------
data "aws_iam_policy_document" "support_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "support" {
  count              = var.hardening ? 1 : 0
  name               = "${var.project}-support"
  description        = "CIS: incident management with AWS Support"
  assume_role_policy = data.aws_iam_policy_document.support_assume.json
}

resource "aws_iam_role_policy_attachment" "support" {
  count      = var.hardening ? 1 : 0
  role       = aws_iam_role.support[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

# ---------- R04: restrictive network ACL on the public subnet (second layer behind the SG) ----------
# Inbound: only return traffic on ephemeral ports (SSM, updates, Tailscale use outbound connections).
# 22 is allowed only while the S3 scenario toggle is on, so the scenarios stay reproducible.
# Outbound: all (CIS checks only inbound; restricting egress would break SSM/Tailscale/package installs).
resource "aws_network_acl" "public" {
  count      = var.hardening ? 1 : 0
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.public.id]
  tags       = { Name = "${var.project}-public-nacl" }
}

resource "aws_network_acl_rule" "in_tcp_ephemeral" {
  count          = var.hardening ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "in_udp_ephemeral" {
  count          = var.hardening ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 110
  egress         = false
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "in_ssh_scenario" {
  count          = var.hardening && var.ssh_open ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 90
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "out_all" {
  count          = var.hardening ? 1 : 0
  network_acl_id = aws_network_acl.public[0].id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

# ---------- Log bucket: VPC flow logs + S3 server access logs of the trail bucket ----------
resource "aws_s3_bucket" "logs" {
  count         = var.hardening ? 1 : 0
  bucket        = local.log_bucket
  force_destroy = true
  tags          = { Name = local.log_bucket }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.hardening ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = var.hardening ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.hardening ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3: log delivery services can't write with a customer KMS key without extra key policy.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.hardening ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.hardening ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    id     = "expire-30d"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

data "aws_iam_policy_document" "logs_bucket" {
  count = var.hardening ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # S3 server access logs (trail bucket) - service principal, no ACLs (BucketOwnerEnforced).
  statement {
    sid       = "S3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/s3-access/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.trail.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # VPC flow logs delivery.
  statement {
    sid       = "FlowLogsWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid       = "FlowLogsAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs[0].arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count      = var.hardening ? 1 : 0
  bucket     = aws_s3_bucket.logs[0].id
  policy     = data.aws_iam_policy_document.logs_bucket[0].json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# CIS logging: S3 server access logging on the CloudTrail bucket.
resource "aws_s3_bucket_logging" "trail" {
  count         = var.hardening ? 1 : 0
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = "s3-access/trail/"
  depends_on    = [aws_s3_bucket_policy.logs]
}

# CIS logging: VPC flow logs (all traffic, 1-minute aggregation).
resource "aws_flow_log" "vpc" {
  count                    = var.hardening ? 1 : 0
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = aws_s3_bucket.logs[0].arn
  max_aggregation_interval = 60
  tags                     = { Name = "${var.project}-vpc-flow-logs" }
  depends_on               = [aws_s3_bucket_policy.logs]
}

output "hardening_state" {
  value = var.hardening ? "ON (log bucket ${local.log_bucket})" : "OFF"
}
