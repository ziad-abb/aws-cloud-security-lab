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
# This is also exactly what an attacker gets in S4 if the role credentials are stolen.
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
