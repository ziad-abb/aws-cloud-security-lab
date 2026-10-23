# Phase 3 - auto-remediation: EventBridge ("AWS API Call via CloudTrail") -> Lambda -> SNS email.
# Lambdas are always deployed; var.lambdas_enabled only switches the EventBridge RULES on/off
# (instant, in-place). L1 = S1 S3 re-block | L2 = S3 SG revoke | L3 = IMDSv2 enforce (keep OFF during S4).
# Cost: Lambda/EventBridge free tier; log groups kept 7 days.

locals {
  lambdas = {
    l1 = {
      name = "${var.project}-l1-s3-reblock"
      file = "l1_s3_reblock"
      pattern = {
        source        = ["aws.s3"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName   = ["PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutBucketPolicy"]
          errorCode   = [{ exists = false }]
        }
      }
      env = { BUCKET_PREFIX = "${var.project}-", OWN_ROLE_NAME = "${var.project}-l1-s3-reblock" }
    }
    l2 = {
      name = "${var.project}-l2-sg-revoke"
      file = "l2_sg_revoke"
      pattern = {
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress"]
          errorCode   = [{ exists = false }]
        }
      }
      env = {}
    }
    l3 = {
      name = "${var.project}-l3-imds-enforce"
      file = "l3_imds_enforce"
      pattern = {
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["ModifyInstanceMetadataOptions", "RunInstances"]
          errorCode   = [{ exists = false }]
        }
      }
      env = {}
    }
  }

  lambda_policies = {
    l1 = data.aws_iam_policy_document.l1.json
    l2 = data.aws_iam_policy_document.l2.json
    l3 = data.aws_iam_policy_document.l3.json
  }
}

# ---------- Code packages ----------
data "archive_file" "lambda" {
  for_each    = local.lambdas
  type        = "zip"
  source_file = "${path.module}/../lambda/${each.value.file}.py"
  output_path = "${path.module}/build/${each.key}.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = local.lambdas
  name              = "/aws/lambda/${each.value.name}"
  retention_in_days = 7
}

# ---------- One least-privilege role per Lambda ----------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  for_each           = local.lambdas
  name               = each.value.name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda" {
  for_each = local.lambdas
  name     = "${each.value.name}-least-priv"
  role     = aws_iam_role.lambda[each.key].id
  policy   = local.lambda_policies[each.key]
}

# L1: read + re-enable Block Public Access, only on seclab-* buckets
data "aws_iam_policy_document" "l1" {
  statement {
    sid       = "BlockPublicAccessOnLabBuckets"
    actions   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
    resources = ["arn:aws:s3:::${var.project}-*"]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda["l1"].arn}:*"]
  }
}

# L2: revoke ingress, only on security groups tagged Project=seclab
data "aws_iam_policy_document" "l2" {
  statement {
    sid       = "Describe"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"]
    resources = ["*"]
  }
  statement {
    sid       = "RevokeOnLabGroupsOnly"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda["l2"].arn}:*"]
  }
}

# L3: enforce IMDSv2, only on instances tagged Project=seclab
data "aws_iam_policy_document" "l3" {
  statement {
    sid       = "Describe"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
  statement {
    sid       = "EnforceImdsOnLabInstancesOnly"
    actions   = ["ec2:ModifyInstanceMetadataOptions"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda["l3"].arn}:*"]
  }
}

# ---------- Functions ----------
resource "aws_lambda_function" "remediation" {
  for_each         = local.lambdas
  function_name    = each.value.name
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = "python3.13"
  handler          = "${each.value.file}.handler"
  filename         = data.archive_file.lambda[each.key].output_path
  source_code_hash = data.archive_file.lambda[each.key].output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = merge({
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      PROJECT_TAG   = var.project
    }, each.value.env)
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# ---------- EventBridge wiring (the toggle) ----------
resource "aws_cloudwatch_event_rule" "remediation" {
  for_each      = local.lambdas
  name          = each.value.name
  description   = "seclab auto-remediation trigger for ${each.value.name}"
  event_pattern = jsonencode(each.value.pattern)
  state         = var.lambdas_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "remediation" {
  for_each = local.lambdas
  rule     = aws_cloudwatch_event_rule.remediation[each.key].name
  arn      = aws_lambda_function.remediation[each.key].arn
}

resource "aws_lambda_permission" "eventbridge" {
  for_each      = local.lambdas
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation[each.key].arn
}
