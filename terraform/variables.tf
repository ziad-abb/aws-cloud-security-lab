# ---------- General ----------
variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "seclab"
}

variable "region" {
  description = "Fixed by the AWS new sign-up experience (Morocco -> Stockholm)"
  type        = string
  default     = "eu-north-1"

  validation {
    condition     = var.region == "eu-north-1"
    error_message = "This account only supports eu-north-1."
  }
}

variable "my_ips" {
  description = "My public IPs in CIDR form (home + phone hotspot). Set in terraform.tfvars, never committed."
  type        = list(string)
  default     = []
}

variable "alert_email" {
  description = "Email that receives SNS alerts. Set in terraform.tfvars."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

# ---------- Network ----------
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

# ---------- Compute ----------
variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "wazuh_manager_ip" {
  description = "Tailscale IP of the Wazuh manager (VM1)"
  type        = string
  default     = "100.125.248.13"
}

variable "wazuh_agent_version" {
  description = "Must not be newer than the manager (4.14.9)"
  type        = string
  default     = "4.14.9-1"
}

variable "tailscale_param_name" {
  description = "SSM SecureString holding the Tailscale auth key (created by hand, never in state)"
  type        = string
  default     = "/seclab/tailscale-authkey"
}

variable "cloudtrail_enabled" {
  description = "Keep true on real AWS. Set false only for LocalStack tests (CloudTrail not in the free license)."
  type        = bool
  default     = true
}

variable "ami_id" {
  description = "Leave empty on real AWS (latest AL2023 via SSM). Set only for LocalStack tests."
  type        = string
  default     = ""
}

# ---------- Scenario toggles (all false = secure baseline) ----------
variable "insecure_bucket" {
  description = "S1: Block Public Access off + public-read bucket policy"
  type        = bool
  default     = false
}

variable "ssh_open" {
  description = "S3: SG rule tcp/22 from 0.0.0.0/0"
  type        = bool
  default     = false
}

variable "imds_v1" {
  description = "Misconfiguration test for L3: http_tokens = optional (IMDSv1 allowed)"
  type        = bool
  default     = false
}

variable "lambdas_enabled" {
  description = "EventBridge rules + auto-remediation Lambdas L1/L2/L3 active"
  type        = bool
  default     = false
}
