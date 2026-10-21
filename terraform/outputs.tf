output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "web_sg_id" {
  value = aws_security_group.web.id
}

output "data_bucket" {
  value = aws_s3_bucket.data.id
}

output "data_kms_key_arn" {
  value = aws_kms_key.data.arn
}

output "web_instance_id" {
  value = aws_instance.web.id
}

output "web_public_ip" {
  value = aws_instance.web.public_ip
}

output "web_role_arn" {
  value = aws_iam_role.web.arn
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "trail_name" {
  value = local.trail_name
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "ssm_command" {
  description = "Open a shell on the instance (no SSH)"
  value       = "aws ssm start-session --target ${aws_instance.web.id}"
}
