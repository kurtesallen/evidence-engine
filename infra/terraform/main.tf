locals {
  object_arn = "${aws_s3_bucket.evidence.arn}/${var.evidence_prefix}/*"

  # GitHub immutable OIDC identity for this repository.
  # These IDs were obtained from the GitHub repository API.
  github_oidc_repository_subject = "repo:${var.github_owner}@76596317/${var.github_repository}@1425093390"

  producer_github_subject = "${local.github_oidc_repository_subject}:environment:${var.producer_environment_name}"
  consumer_github_subject = "${local.github_oidc_repository_subject}:environment:${var.consumer_environment_name}"
}

data "aws_partition" "current" {}

# Reuse the existing account-level GitHub Actions OIDC provider.
# This configuration reads the provider but does not manage or create it.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_s3_bucket" "evidence" {
  bucket        = var.bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "evidence_encryption" {
  description              = "EvidenceEngine S3 evidence-bundle encryption key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = 30

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "evidence_encryption" {
  name          = "alias/${var.project_name}-evidence-encryption"
  target_key_id = aws_kms_key.evidence_encryption.key_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_encryption.arn
    }

    bucket_key_enabled       = true
    blocked_encryption_types = ["SSE-C"]
  }
}

# The application supplies the SSE-KMS algorithm and key ARN with each
# PutObject call. Deny requests that omit or mismatch the encryption headers.
#
# Encryption-header restrictions apply only to the EvidenceEngine prefix.
# The HTTPS-only restriction remains in force for the entire bucket.
data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.evidence.arn,
      "${aws_s3_bucket.evidence.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyMissingSSEHeader"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = [local.object_arn]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  statement {
    sid    = "DenyNonKmsEncryption"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = [local.object_arn]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid    = "DenyMissingSSEKMSKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = [local.object_arn]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["true"]
    }
  }

  statement {
    sid    = "DenyWrongSSEKMSKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = [local.object_arn]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.evidence_encryption.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence_bucket.json
}

# Dedicated asymmetric key for manifest signatures.
# The private key material remains inside AWS KMS.
resource "aws_kms_key" "signing" {
  description              = "EvidenceEngine asymmetric evidence-signing key"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false
  deletion_window_in_days  = 30

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${var.project_name}-evidence-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# Exporting the public key is safe; private key material remains in KMS.
# The public PEM can be placed in the locally managed trust registry.
data "aws_kms_public_key" "signing" {
  key_id = aws_kms_key.signing.arn
}

resource "aws_kms_key" "acceptance_encryption" {
  description              = "EvidenceEngine DynamoDB acceptance table encryption key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = 30

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "acceptance_encryption" {
  name          = "alias/${var.project_name}-acceptance-encryption"
  target_key_id = aws_kms_key.acceptance_encryption.key_id
}

resource "aws_dynamodb_table" "acceptance" {
  name                        = "${var.project_name}-acceptance"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.acceptance_encryption.arn
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Trust only the exact repository and protected GitHub Environment subject.
# Configure branch restrictions and required reviewers in GitHub.
data "aws_iam_policy_document" "producer_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.producer_github_subject]
    }
  }
}

data "aws_iam_policy_document" "consumer_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.consumer_github_subject]
    }
  }
}

resource "aws_iam_role" "producer" {
  name                 = "${var.project_name}-producer"
  assume_role_policy   = data.aws_iam_policy_document.producer_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "producer" {
  name   = "${var.project_name}-producer-evidence-access"
  role   = aws_iam_role.producer.id
  policy = data.aws_iam_policy_document.producer_permissions.json
}

data "aws_iam_policy_document" "producer_permissions" {
  statement {
    sid       = "UploadEvidenceBundleObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = [local.object_arn]
  }

  # S3 Bucket Keys use the bucket ARN as the KMS encryption context.
  # Restrict data-key generation to S3 and this evidence bucket.
  statement {
    sid    = "GenerateEvidenceEncryptionDataKeys"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [aws_kms_key.evidence_encryption.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${var.aws_region}.${data.aws_partition.current.dns_suffix}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [aws_s3_bucket.evidence.arn]
    }
  }

  # Match the signing implementation: RSA-PSS with SHA-256 over a digest.
  statement {
    sid       = "SignEvidenceManifests"
    effect    = "Allow"
    actions   = ["kms:Sign"]
    resources = [aws_kms_key.signing.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["RSASSA_PSS_SHA_256"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }
  }
}

resource "aws_iam_role" "consumer" {
  name                 = "${var.project_name}-consumer"
  assume_role_policy   = data.aws_iam_policy_document.consumer_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "consumer" {
  name   = "${var.project_name}-consumer-evidence-access"
  role   = aws_iam_role.consumer.id
  policy = data.aws_iam_policy_document.consumer_permissions.json
}

data "aws_iam_policy_document" "consumer_permissions" {
  statement {
    sid       = "ReadVersionedEvidenceBundleObjects"
    effect    = "Allow"
    actions   = ["s3:GetObjectVersion"]
    resources = [local.object_arn]
  }

  # Permit S3-mediated decryption for this bucket's configured Bucket Key.
  statement {
    sid       = "DecryptEvidenceBundleObjects"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.evidence_encryption.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${var.aws_region}.${data.aws_partition.current.dns_suffix}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [aws_s3_bucket.evidence.arn]
    }
  }

  # Supports legacy single-item acceptance, atomic ordered acceptance,
  # and strongly consistent checkpoint inspection in the synthetic E2E test.
  statement {
    sid    = "RecordAndInspectAcceptedBundleState"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:TransactWriteItems",
      "dynamodb:GetItem",
    ]
    resources = [aws_dynamodb_table.acceptance.arn]
  }

  # Permit the consumer role to use this key only through DynamoDB and only
  # for the acceptance table. Key use remains separate from S3 encryption
  # and the asymmetric evidence-signing key.
  statement {
    sid    = "UseAcceptanceKeyThroughDynamoDB"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.acceptance_encryption.arn]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["dynamodb.*.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:dynamodb:tableName"
      values   = [aws_dynamodb_table.acceptance.name]
    }
  }

  # DynamoDB may create grants for its managed use of the key. Restrict
  # grant creation to AWS-resource requests routed through DynamoDB.
  statement {
    sid       = "CreateAcceptanceKeyGrantForDynamoDB"
    effect    = "Allow"
    actions   = ["kms:CreateGrant"]
    resources = [aws_kms_key.acceptance_encryption.arn]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["dynamodb.*.amazonaws.com"]
    }
  }
}
# New evidence object versions receive 30 days of Governance Mode retention.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 30
    }
  }

  # S3 Object Lock requires bucket versioning.
  depends_on = [aws_s3_bucket_versioning.evidence]

  lifecycle {
    prevent_destroy = true
  }
}
