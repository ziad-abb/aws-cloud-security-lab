terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Every resource gets these tags: easy cost tracking and cleanup checks.
  default_tags {
    tags = {
      Project   = var.project
      Owner     = "ziad-abbassi"
      ManagedBy = "terraform"
    }
  }
}
