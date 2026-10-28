variable "aws_region" {
  description = "AWS Region for EvidenceEngine resources."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = length(trimspace(var.aws_region)) > 0
    error_message = "aws_region must not be empty."
  }
}

variable "project_name" {
  description = "Lowercase project identifier used in resource names and tags."
  type        = string
  default     = "evidence-engine"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$", var.project_name))
    error_message = "project_name must use lowercase letters, digits, and hyphens, and start with a letter."
  }
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name dedicated to EvidenceEngine evidence bundles."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be 3-63 characters and use lowercase letters, digits, or hyphens, beginning and ending with a letter or digit."
  }
}

variable "evidence_prefix" {
  description = "S3 key prefix to which producer and consumer IAM roles are limited. Do not include leading or trailing slashes."
  type        = string
  default     = "evidence-engine"

  validation {
    condition = (
      length(trimspace(var.evidence_prefix)) > 0 &&
      var.evidence_prefix == trim(var.evidence_prefix, "/") &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$", var.evidence_prefix)) &&
      alltrue([for part in split("/", var.evidence_prefix) : part != "." && part != ".."])
    )
    error_message = "evidence_prefix must be a normalized relative S3 prefix without leading/trailing slashes or dot/traversal segments."
  }
}

variable "github_owner" {
  description = "Exact GitHub user or organization name that owns the repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.github_owner))
    error_message = "github_owner must contain only letters, digits, or hyphens."
  }
}

variable "github_repository" {
  description = "Exact GitHub repository name, without the owner."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must contain only letters, digits, underscores, periods, or hyphens."
  }
}

variable "producer_environment_name" {
  description = "GitHub Actions Environment subject allowed to assume the producer IAM role. Configure this environment with protected deployment branches and approvals."
  type        = string
  default     = "evidence-producer"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.producer_environment_name))
    error_message = "producer_environment_name may contain only letters, digits, underscores, and hyphens."
  }
}

variable "consumer_environment_name" {
  description = "GitHub Actions Environment subject allowed to assume the consumer IAM role. Configure this environment with protected deployment branches and approvals."
  type        = string
  default     = "evidence-consumer"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.consumer_environment_name))
    error_message = "consumer_environment_name may contain only letters, digits, underscores, and hyphens."
  }
}

variable "tags" {
  description = "Additional tags applied to supported AWS resources."
  type        = map(string)
  default = {
    Application = "EvidenceEngine"
  }
}
