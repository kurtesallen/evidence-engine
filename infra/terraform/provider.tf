provider "aws" {
  region              = var.aws_region
  allowed_account_ids = ["846470648858"]

  default_tags {
    tags = merge(var.tags, {
      Project   = var.project_name
      ManagedBy = "Terraform"
    })
  }
}