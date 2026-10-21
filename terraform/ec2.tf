# CIS: every new EBS volume in the region is encrypted by default.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# Latest Amazon Linux 2023 AMI, unless ami_id is set (LocalStack tests).
data "aws_ssm_parameter" "al2023" {
  count = var.ami_id == "" ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  web_ami = var.ami_id != "" ? var.ami_id : nonsensitive(data.aws_ssm_parameter.al2023[0].value)
}

resource "aws_instance" "web" {
  ami                         = local.web_ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.web.name
  associate_public_ip_address = true # needed to reach SSM without a NAT Gateway
  # No key_name: there is no SSH key at all. Admin access = SSM only.

  # S4 toggle. Baseline = IMDSv2 required (session token needed, SSRF-resistant).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = var.imds_v1 ? "optional" : "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  # Cost guard: "standard" credits = no surprise charges if the CPU stays busy.
  credit_specification {
    cpu_credits = "standard"
  }

  tags = { Name = "${var.project}-web" }

  lifecycle {
    # A newer AMI must not replace the instance in the middle of the lab.
    ignore_changes = [ami]
  }

  depends_on = [aws_ebs_encryption_by_default.this]
}
