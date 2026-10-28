# EvidenceEngine AWS infrastructure (initial Terraform root)

This configuration defines the initial AWS resources for versioned evidence bundles, KMS-backed signing/encryption, durable replay detection, and GitHub Actions OIDC roles. It is a starting point for review and validation, not an instruction to provision resources immediately.

## Resources defined

- A private S3 bucket with public access blocked, bucket-owner-enforced object ownership, versioning, TLS-only access, and SSE-KMS encryption using a dedicated symmetric key.
- A separate asymmetric RSA-2048 KMS key with `SIGN_VERIFY` usage. The producer role receives only `kms:Sign`; the private key is never exported. Terraform can expose the public PEM for the local trust registry.
- A DynamoDB acceptance table keyed by the string attribute `bundle_digest`, with on-demand capacity, point-in-time recovery, deletion protection, and server-side encryption.
- Separate producer and consumer IAM roles. Producer access is restricted to `s3:PutObject` under the configured evidence prefix, `kms:GenerateDataKey` for the S3 encryption key, and `kms:Sign` for the signing key. Consumer access is restricted to `s3:GetObjectVersion` under that prefix, `kms:Decrypt` for the S3 encryption key, and `dynamodb:PutItem` for the acceptance table.
- A GitHub OIDC provider and environment-scoped trust policies. Producer and consumer roles trust different exact OIDC `sub` values.

The S3 bucket, KMS keys, DynamoDB table, and OIDC provider have Terraform `prevent_destroy` safeguards. The bucket and table are not configured for automatic evidence expiry. Versioning preserves old object versions but is not a substitute for S3 Object Lock or protection against privileged deletion.

## Before using this configuration

1. Confirm the AWS account and region with your administrator.
2. Check whether `token.actions.githubusercontent.com` already exists as an IAM OIDC provider in that AWS account. The issuer is account-wide. If it already exists, import and manage the existing provider instead of trying to create a duplicate.
3. Create the GitHub Environments `evidence-producer` and `evidence-consumer`. Restrict allowed deployment branches to the protected default branch (typically `main`), and configure required reviewers or other appropriate protection rules. AWS trust policy conditions require the corresponding environment subjects.
4. Ensure the GitHub owner and repository values exactly match the repository that will request the OIDC token.
5. Decide on a separate, secured Terraform state backend before applying this root. No remote backend is configured here; the root would otherwise use local state. Do not share local state or commit it. A separate state-bootstrap configuration should use an S3 state bucket with versioning and S3 native lockfile support, or an organization-approved remote backend.
6. Review IAM, retention requirements, backup/recovery expectations, budget, and regional constraints before applying. S3 versioning alone does not prevent administrators from permanently deleting object versions. Enable S3 Object Lock only after the desired retention and legal-hold policy is defined.

## Configure local inputs

From this directory, copy the example and edit the values:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Set a globally unique `bucket_name`, the actual GitHub owner and repository, and the chosen AWS region. `terraform.tfvars` is ignored by the included `.gitignore`.

## Validate without provisioning

Use a current Terraform CLI (1.6 or later):

```bash
terraform fmt -recursive -check
terraform init -backend=false
terraform validate
```

`terraform init -backend=false` downloads provider plugins but does not create AWS resources. `terraform validate` checks Terraform configuration syntax and internal consistency. It does not prove the credentials, permissions, GitHub environment protections, AWS quotas, global bucket-name availability, or remote state setup are correct.

Do not run `terraform apply` during this validation phase. A later review should include a real plan under the intended AWS account and an explicit approval before provisioning.

After initialization, review and commit `.terraform.lock.hcl` to pin the selected provider dependency. Do not commit `.terraform/`, `terraform.tfvars`, local state, credentials, or generated plan files.

## Application configuration after approved provisioning

Use Terraform outputs for the bucket, S3 KMS key ARN, signing key ARN, acceptance table, and role ARNs. Configure the producer with the evidence prefix and KMS signing mode. Configure the consumer with the same S3 bucket/key settings, `EVIDENCE_ENGINE_ACCEPTANCE_BACKEND=dynamodb`, and `EVIDENCE_ENGINE_DYNAMODB_TABLE` set to the table output. The application still needs a locally controlled trust registry whose `key_id` matches the signing key ARN and whose public key is the exported KMS public PEM.

This Terraform root does not yet configure a deployment workflow or GitHub repository/environment settings. A future workflow must use the matching GitHub Environment and request short-lived credentials through OIDC. Do not add long-lived AWS access keys to repository secrets.
