output "evidence_bucket_name" {
  description = "S3 bucket used for EvidenceEngine bundles."
  value       = aws_s3_bucket.evidence.bucket
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence bundle bucket."
  value       = aws_s3_bucket.evidence.arn
}

output "evidence_prefix" {
  description = "Prefix under which producer and consumer roles may write/read bundles."
  value       = var.evidence_prefix
}

output "s3_kms_key_arn" {
  description = "Use as EVIDENCE_ENGINE_S3_KMS_KEY_ID."
  value       = aws_kms_key.evidence_encryption.arn
}

output "signing_kms_key_arn" {
  description = "Use as the producer KMS signing key ID and manifest key_id."
  value       = aws_kms_key.signing.arn
}

output "signing_public_key_pem" {
  description = "Public PEM for the locally controlled trust registry; public key material is not secret."
  value       = data.aws_kms_public_key.signing.public_key_pem
}

output "acceptance_table_name" {
  description = "Use as EVIDENCE_ENGINE_DYNAMODB_TABLE."
  value       = aws_dynamodb_table.acceptance.name
}

output "producer_role_arn" {
  description = "Role ARN for the protected producer GitHub Environment."
  value       = aws_iam_role.producer.arn
}

output "consumer_role_arn" {
  description = "Role ARN for the protected consumer GitHub Environment."
  value       = aws_iam_role.consumer.arn
}

output "producer_github_subject" {
  description = "Exact GitHub OIDC sub claim trusted by the producer role."
  value       = local.producer_github_subject
}

output "consumer_github_subject" {
  description = "Exact GitHub OIDC sub claim trusted by the consumer role."
  value       = local.consumer_github_subject
}
