# EvidenceEngine Terraform State Bootstrap

This directory is a separate Terraform root for creating the remote state backend used by the EvidenceEngine infrastructure root. It is intentionally separate from `infra/terraform`, which manages the evidence bucket, evidence encryption/signing keys, acceptance table, and GitHub OIDC roles.

## Resources defined

- A dedicated S3 state bucket with versioning, all four S3 Block Public Access settings, bucket-owner-enforced ownership, and a deny-insecure-transport bucket policy.
- Default SSE-KMS encryption using a dedicated symmetric KMS key with automatic rotation.
- `prevent_destroy` safeguards on the state bucket and KMS key.
- A plan-time account guard that compares the actual AWS account ID with `expected_account_id`.
- Native S3 state locking instructions using Terraform's `use_lockfile = true`; no DynamoDB lock table is created for Terraform locking.

## Configure and validate locally (no AWS writes)

1. Verify the intended AWS account:

   ```bash
   aws sts get-caller-identity --query Account --output text --no-cli-pager
   ```

2. From this directory, copy the example and edit the values:

   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

   Set `expected_account_id` to the exact 12-digit account you verified. Choose a new globally unique state bucket name; do not reuse the existing `evidence-engine` evidence bucket.

3. Format, initialize without a backend, validate, and create a plan for review:

   ```bash
   terraform fmt -recursive
   terraform init -backend=false
   terraform validate
   terraform plan -out=bootstrap.tfplan
   terraform show bootstrap.tfplan
   ```

These commands do not create infrastructure. `plan` may make read-only AWS API calls to check the caller identity and provider metadata. **Do not run `terraform apply` until the plan is reviewed and provisioning is explicitly approved.**

## After the bootstrap resources are approved and created

The bootstrap root initially has local state. After a reviewed and approved apply, inspect outputs:

```bash
terraform output -raw state_bucket_name
terraform output -raw state_kms_key_arn
```

Copy `backend.tf.example` to `backend.tf`, replace the bucket and KMS placeholders with those exact outputs, review it, then migrate the bootstrap root's existing local state:

```bash
terraform init -migrate-state
```

Read Terraform's migration prompt carefully; this is a state write to the new remote backend. Do not delete the local backup until remote state has been verified.

## Configure the main EvidenceEngine root afterwards

Only after the remote backend is established, add a backend block to `infra/terraform` using the same state bucket and KMS key but a separate key:

```hcl
terraform {
  backend "s3" {
    bucket       = "REPLACE_WITH_state_bucket_name"
    key          = "evidence-engine/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    kms_key_id   = "REPLACE_WITH_state_kms_key_arn"
    use_lockfile = true
  }
}
```

Then reinitialize that root. The existing evidence bucket must be imported into the main root's remote state before reconciling its existing configuration. Inspect the plan before any apply. Do not apply the current main-root plan that proposes creating `evidence-engine` as a new bucket.

## Notes

- The state bucket name must be globally unique in the standard S3 bucket namespace.
- Terraform state may contain sensitive values. Restrict read access to the backend bucket and state/lock objects to trusted operators and deployment identities.
- The state KMS key and bucket are intentionally protected from Terraform destruction. Key policy and IAM permissions must allow the intended backend users to use the state key.
- This package has not been applied to AWS. Validation should be performed in the local environment before provisioning.
