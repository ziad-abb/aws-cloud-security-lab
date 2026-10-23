# ---------- lab-web-role: identity of the EC2 instance ----------
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web" {
  name               = "lab-web-role"
  description        = "EC2 web instance role: SSM access + read the data bucket"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# SSM Session Manager: replaces SSH (no port 22, no key pair).
resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# What the app legitimately needs: read the customer files.
# This is also exactly what an attacker gets if the role credentials are ever stolen (blast radius).
data "aws_iam_policy_document" "web_data_read" {
  statement {
    sid       = "ListDataBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn]
  }

  statement {
    sid       = "ReadDataObjects"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }

  statement {
    sid       = "DecryptDataKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
  }

  # Boot-time only: read the Tailscale auth key (SecureString, AWS-managed aws/ssm key).
  # Known risk: stolen role credentials can read it too -> documented, mitigated in Phase 5 (tagged key + Tailscale ACL).
  statement {
    sid       = "ReadTailscaleAuthKey"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.tailscale_param_name}"]
  }
}

resource "aws_iam_role_policy" "web_data_read" {
  name   = "lab-web-data-read"
  role   = aws_iam_role.web.id
  policy = data.aws_iam_policy_document.web_data_read.json
}

resource "aws_iam_instance_profile" "web" {
  name = "lab-web-profile"
  role = aws_iam_role.web.name
}
