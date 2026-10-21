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
