terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }

  backend "s3" {
    bucket              = "evidence-engine-tfstate-846470648858-us-east-1-an"
    key                 = "evidence-engine/terraform.tfstate"
    region              = "us-east-1"
    encrypt             = true
    kms_key_id          = "arn:aws:kms:us-east-1:846470648858:key/e7195e8d-56cf-4c35-990f-ff1daaa0278b"
    use_lockfile        = true
    allowed_account_ids = ["846470648858"]
  }
}