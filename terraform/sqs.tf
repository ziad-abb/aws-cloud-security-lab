# Trail-file notifications for Wazuh (fixes the aws-s3 module's out-of-order gap).
# S3 -> SQS on every new CloudTrail log file -> VM1 reader (wazuh/trail_sqs_reader.py) by ARRIVAL order.
# Cost: SQS free tier (1M requests/month); the reader long-polls once a minute.

resource "aws_sqs_queue" "trail_events_dlq" {
  name                      = "${var.project}-trail-events-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600 # 14 days: time to investigate files that failed 5 times
}

resource "aws_sqs_queue" "trail_events" {
  name                       = "${var.project}-trail-events"
  sqs_managed_sse_enabled    = true # SSE-SQS: encrypted at rest, no KMS key policy needed for S3
  receive_wait_time_seconds  = 20   # long polling = fewer empty requests
  visibility_timeout_seconds = 120  # time for the reader to download + write one file
  message_retention_seconds  = 345600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.trail_events_dlq.arn
    maxReceiveCount     = 5
  })
}

data "aws_iam_policy_document" "trail_events_queue" {
  statement {
    sid       = "AllowTrailBucketNotifications"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.trail_events.arn]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.trail.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sqs_queue_policy" "trail_events" {
  queue_url = aws_sqs_queue.trail_events.id
  policy    = data.aws_iam_policy_document.trail_events_queue.json
}

# Only real log files (CloudTrail/), not the hourly digest files (CloudTrail-Digest/).
resource "aws_s3_bucket_notification" "trail" {
  bucket = aws_s3_bucket.trail.id

  queue {
    queue_arn     = aws_sqs_queue.trail_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "AWSLogs/${local.account_id}/CloudTrail/"
    filter_suffix = ".json.gz"
  }

  depends_on = [aws_sqs_queue_policy.trail_events]
}
