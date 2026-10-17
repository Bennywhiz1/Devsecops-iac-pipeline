# Hardened version of the same four building blocks as terraform/insecure.
# Every control that is skipped below carries a written justification -
# a skip without a reason is itself treated as a policy violation.
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

variable "admin_cidr" {
  description = "The only network allowed to SSH in (e.g. a VPN or office range)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "vpc_id" {
  type    = string
  default = "vpc-12345678"
}

variable "subnet_id" {
  type    = string
  default = "subnet-12345678"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Encryption key: rotation on, explicit least-privilege key policy
# ---------------------------------------------------------------------------
resource "aws_kms_key" "main" {
  description             = "Hardened data key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = [
          "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
          "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
          "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        ]
        Resource = "*"
      },
      {
        Sid       = "AllowEncryptDecryptViaS3"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-1.amazonaws.com" } }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Log bucket (receives access logs for the data bucket)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:This IS the access-log destination; logging it to itself is circular
  #checkov:skip=CKV_AWS_144:Cross-region replication of access logs is not justified by cost for this workload
  #checkov:skip=CKV2_AWS_62:Event notifications are not required on a log-only bucket
  bucket = "example-hardened-logs-bucket"

  tags = {
    Owner       = "platform-team"
    Environment = "demo"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Data bucket: private, encrypted, versioned, logged
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "data" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for this example and doubles storage cost
  #checkov:skip=CKV2_AWS_62:No downstream consumers need event notifications for this bucket
  bucket = "example-hardened-data-bucket"

  tags = {
    Owner       = "platform-team"
    Environment = "demo"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-access/"
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Network: SSH only from the admin range, described rules, attached to an ENI
# ---------------------------------------------------------------------------
resource "aws_security_group" "web" {
  name        = "hardened-web-sg"
  description = "Restricted access for the web tier"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from the admin network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_interface" "web" {
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.web.id]
}

# ---------------------------------------------------------------------------
# IAM: least privilege - two actions, one bucket, nothing else
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "app" {
  name = "hardened-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.data.arn}/*"
    }]
  })
}
