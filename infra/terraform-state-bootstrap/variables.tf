variable "aws_region" {
  description = "Region used for the Terraform state bucket and its KMS key."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = length(trimspace(var.aws_region)) > 0
    error_message = "aws_region must not be empty."
  }
}

variable "expected_account_id" {
  description = "12-digit AWS account ID expected to own this state backend."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be exactly 12 digits."
  }
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name dedicated to Terraform state."
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63 && can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be 3-63 lowercase letters, digits, or hyphens and start/end with a letter or digit."
  }
}

variable "project_name" {
  description = "Lowercase identifier used in the state KMS alias and tags."
  type        = string
  default     = "evidence-engine"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$", var.project_name))
    error_message = "project_name must be lowercase and use letters, digits, and hyphens."
  }
}

variable "tags" {
  description = "Additional tags applied to supported state backend resources."
  type        = map(string)
  default = {
    Application = "EvidenceEngine"
  }
}
