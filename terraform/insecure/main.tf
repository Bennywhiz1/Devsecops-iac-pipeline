# ===========================================================================
# DELIBERATELY INSECURE - FOR SCANNER DEMONSTRATION ONLY.
# DO NOT `terraform apply` THIS. Every resource below contains a common,
# real-world misconfiguration that the security pipeline is expected to catch.
# ===========================================================================
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Flaw: bucket is publicly readable, unencrypted, unversioned, no access block
resource "aws_s3_bucket" "data" {
  bucket = "example-insecure-data-bucket"
  acl    = "public-read"
}

# Flaw: SSH open to the entire internet, unrestricted egress, no description
resource "aws_security_group" "web" {
  name   = "insecure-web-sg"
  vpc_id = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Flaw: wildcard admin policy (Action * on Resource *)
resource "aws_iam_policy" "admin" {
  name = "insecure-admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Flaw: customer-managed key with rotation disabled
resource "aws_kms_key" "main" {
  description         = "insecure key"
  enable_key_rotation = false
}
