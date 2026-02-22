# Minimal Terraform fixture for Checkov E2E testing.
# Intentionally simple — gives Checkov something real to evaluate
# without introducing intentional vulnerabilities into the repo.

terraform {
  required_version = ">= 1.0"
}

resource "aws_s3_bucket" "test" {
  bucket = "argus-e2e-test-bucket"

  tags = {
    Environment = "test"
    Purpose     = "e2e-checkov-fixture"
  }
}

resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
  bucket = aws_s3_bucket.test.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
