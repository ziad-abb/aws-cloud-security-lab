# Alert topic: the Lambdas (Phase 3) publish here, you get an email.
resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-alerts"
  kms_master_key_id = "alias/aws/sns" # encryption at rest (Prowler check)
  # Note: EventBridge can't publish directly to a topic using the AWS-managed key.
  # Our flow is EventBridge -> Lambda -> SNS, so this is fine.
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
  # AWS sends a confirmation email: click the link once per new topic.
}
