output "current_account_id" {
  description = "AWS account ID observed by the configured credentials."
  value       = data.aws_caller_identity.current.account_id
}

output "state_bucket_name" {
  description = "S3 bucket name for Terraform remote state."
  value       = aws_s3_bucket.state.bucket
}

output "state_bucket_arn" {
  description = "ARN of the Terraform state bucket."
  value       = aws_s3_bucket.state.arn
}

output "state_kms_key_arn" {
  description = "KMS key ARN to use as kms_key_id in the S3 backend configuration."
  value       = aws_kms_key.state.arn
}

output "bootstrap_state_key" {
  description = "Suggested key for this bootstrap root's own remote state."
  value       = "bootstrap/terraform.tfstate"
}

output "evidence_engine_state_key" {
  description = "Suggested state key for the EvidenceEngine infrastructure root."
  value       = "evidence-engine/terraform.tfstate"
}
