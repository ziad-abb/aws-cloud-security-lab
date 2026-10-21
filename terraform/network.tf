data "aws_availability_zones" "available" {
  state = "available"
}

# ---------- VPC ----------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true # required for SSM endpoints
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

# Lock down the VPC's default security group (CIS: default SG must allow no traffic).
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress / egress blocks = all rules removed.
  tags = { Name = "${var.project}-default-sg-locked" }
}

# ---------- Internet access (no NAT Gateway: cost rule) ----------
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  # No auto public IP: the EC2 instance asks for one explicitly.
  map_public_ip_on_launch = false

  tags = { Name = "${var.project}-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------- Security group for the web EC2 ----------
# Baseline: NO inbound rules at all. Admin access = SSM only (outbound HTTPS).
resource "aws_security_group" "web" {
  name        = "${var.project}-web-sg"
  description = "Web instance: no inbound by default, SSM over outbound 443"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Outbound for SSM, package updates, Wazuh agent via Tailscale"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-web-sg" }
}

# S3 scenario toggle: SSH open to the world (deliberate misconfiguration).
resource "aws_vpc_security_group_ingress_rule" "ssh_open" {
  count             = var.ssh_open ? 1 : 0
  security_group_id = aws_security_group.web.id
  description       = "S3 scenario - INSECURE"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

# S4 scenario toggle: Flask app port open only to my own IPs.
resource "aws_vpc_security_group_ingress_rule" "app_from_me" {
  for_each          = var.vuln_app ? toset(var.my_ips) : toset([])
  security_group_id = aws_security_group.web.id
  description       = "S4 scenario - app port from my IPs only"
  ip_protocol       = "tcp"
  from_port         = 5000
  to_port           = 5000
  cidr_ipv4         = each.value
}
