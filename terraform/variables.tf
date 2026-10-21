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

# ---------- Network ----------
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
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
  description = "S4: http_tokens = optional (IMDSv1 allowed)"
  type        = bool
  default     = false
}

variable "vuln_app" {
  description = "S4: deploy the SSRF-vulnerable Flask route and open the app port to my_ips"
  type        = bool
  default     = false
}

variable "lambdas_enabled" {
  description = "S1/S3: EventBridge rules + auto-remediation Lambdas active"
  type        = bool
  default     = false
}
