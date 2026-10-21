# Customer-managed key for the "sensitive" copy of the customer file.
# Cost: ~$1/month, prorated per hour. Not charged while pending deletion.
resource "aws_kms_key" "data" {
  description             = "${var.project} data bucket key (clients-kms.csv)"
  enable_key_rotation     = true # CIS: rotation on customer-managed keys
  deletion_window_in_days = 7    # minimum, so destroy/apply cycles stay cheap

  tags = { Name = "${var.project}-data-key" }
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.project}-data"
  target_key_id = aws_kms_key.data.key_id
}
