locals {
  account_id   = data.aws_caller_identity.current.account_id
  trail_name   = "${var.project}-trail"
  trail_arn    = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  trail_bucket = "${var.project}-trail-${local.account_id}"
}

# ---------- KMS key for the log files (CIS: trail logs encrypted with a CMK) ----------
data "aws_iam_policy_document" "trail_key" {
  # Account keeps full control (lets IAM policies grant decrypt, e.g. wazuh-reader later).
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudTrail may encrypt, only for this account's trail.
  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudTrailDescribe"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "trail" {
  description             = "${var.project} CloudTrail log files"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.trail_key.json

  tags = { Name = "${var.project}-trail-key" }
}

resource "aws_kms_alias" "trail" {
  name          = "alias/${var.project}-trail"
  target_key_id = aws_kms_key.trail.key_id
}

# ---------- Trail bucket (separate from the data bucket) ----------
resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true # lab only

  tags = { Name = local.trail_bucket, DataClass = "audit-logs" }
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled" # a deleted/overwritten log file can still be recovered
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true # fewer KMS calls = lower cost
  }
}

# Cost guard: logs older than 30 days are deleted (the lab lasts weeks, not years).
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-old-logs"
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

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*",
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
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

# ---------- The trail ----------
resource "aws_cloudtrail" "main" {
  count = var.cloudtrail_enabled ? 1 : 0 # false only for LocalStack (CloudTrail not in the free license)

  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id
  kms_key_id     = aws_kms_key.trail.arn

  is_multi_region_trail         = false # multi-region not allowed on this account
  include_global_service_events = true  # try to capture IAM events (to verify in Phase 1)
  enable_log_file_validation    = true  # digest files prove logs weren't altered (CIS)

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # S3 data events on the DATA bucket only (GetObject etc. -> S1 and S2 detection).
    # Not on the trail bucket itself, which would log its own writes in a loop.
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.data.arn}/"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.trail,
    aws_kms_key.trail,
  ]
}
