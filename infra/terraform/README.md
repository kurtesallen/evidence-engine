# EvidenceEngine AWS infrastructure (initial Terraform root)

This configuration defines the initial AWS resources for versioned evidence bundles, KMS-backed signing and encryption, durable replay and rollback detection, and GitHub Actions OIDC roles. It is intended for architecture review and validation, not as an instruction to provision resources immediately.

## Resources defined

- A private Amazon S3 bucket with public access blocked, bucket-owner-enforced object ownership, versioning, TLS-only access, and SSE-KMS encryption using a dedicated symmetric KMS key.
- A separate asymmetric RSA-2048 KMS key with `SIGN_VERIFY` usage for evidence signing. The producer role receives permission to call `kms:Sign`; the private key is never exported. Terraform can expose the public key in PEM format for the local trust registry.
- A DynamoDB acceptance table with a composite primary key consisting of the string partition key `pk` and string sort key `sk`. Each accepted bundle has a `bundle_digest` attribute containing its SHA-256 digest. Digest records use a sort key in the form `DIGEST#<bundle_digest>`, while checkpoint records use `CHECKPOINT#<stream_id>`. The table uses on-demand capacity, point-in-time recovery, deletion protection, and server-side encryption with a dedicated KMS key.
- Separate producer and consumer IAM roles with narrowly scoped permissions:
  - **Producer:** `s3:PutObject` under the configured evidence prefix, `kms:GenerateDataKey` for the S3 encryption key, and `kms:Sign` for the asymmetric evidence-signing key.
  - **Consumer:** `s3:GetObjectVersion` under the configured evidence prefix, `kms:Decrypt` for the S3 encryption key, and `dynamodb:PutItem` plus `dynamodb:TransactWriteItems` for the acceptance table. `TransactWriteItems` supports atomic digest acceptance and ordered checkpoint updates; `PutItem` supports the adapter's single-item acceptance operation.
- A GitHub OIDC provider and environment-scoped trust policies. The producer and consumer roles trust different, explicitly defined OIDC subject values.

The S3 bucket, KMS keys, DynamoDB table, and OIDC provider have Terraform `prevent_destroy` safeguards. The bucket and table are not configured for automatic evidence expiry. S3 versioning preserves previous object versions, but it does not prevent privileged users from permanently deleting those versions and is not a substitute for S3 Object Lock.

## Before using this configuration

1. Confirm the AWS account and region with your administrator.
2. Check whether `token.actions.githubusercontent.com` already exists as an IAM OIDC provider in the AWS account. The issuer is account-wide. If it already exists, import and manage the existing provider rather than attempting to create a duplicate.
3. Create the GitHub Environments `evidence-producer` and `evidence-consumer`. Restrict allowed deployment branches to the protected default branch and configure required reviewers or other appropriate environment protections. The AWS trust policies require the corresponding environment-scoped OIDC subjects.
4. Ensure the GitHub owner and repository values exactly match the repository requesting the OIDC token.
5. Configure a separate, secured Terraform state backend before applying this root. No remote backend is configured here, so Terraform would otherwise use local state. Do not share local state or commit it. A separate state-bootstrap configuration should use an S3 state bucket with versioning and native S3 lockfile support, or another organization-approved remote backend.
6. Review IAM permissions, evidence-retention requirements, backup and recovery expectations, budget, and regional constraints before applying. S3 versioning alone does not prevent administrators from permanently deleting object versions. Enable S3 Object Lock only after the required retention period, governance or compliance mode, and legal-hold policy have been defined.
7. Confirm that the consumer role's DynamoDB permissions include `dynamodb:TransactWriteItems`. The ordered acceptance implementation uses a DynamoDB transaction to atomically record a bundle digest and advance its stream checkpoint.

## Configure local inputs

From this directory, copy the example variables file and edit the values:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Set a globally unique `bucket_name`, the actual GitHub owner and repository, and the selected AWS region. The `terraform.tfvars` file is ignored by the included `.gitignore`.

## Validate without provisioning

Use a current Terraform CLI (1.6 or later):

```bash
terraform fmt -recursive -check
terraform init -backend=false
terraform validate
```

`terraform init -backend=false` downloads the required provider plugins but does not create AWS resources. `terraform validate` checks Terraform configuration syntax and internal consistency. Neither command proves that AWS credentials, IAM permissions, GitHub environment protections, AWS quotas, global bucket-name availability, or remote state configuration are correct.

Do not run `terraform apply` during this validation phase. A later review should include a Terraform plan under the intended AWS account and an explicit approval before provisioning.

After initialization, review and commit `.terraform.lock.hcl` to pin the selected provider dependency. Do not commit `.terraform/`, `terraform.tfvars`, local state, credentials, or generated plan files.

## Application configuration after approved provisioning

Use Terraform outputs for the S3 bucket, S3 KMS key ARN, signing key ARN, acceptance table name, and IAM role ARNs.

Configure the producer with the evidence bucket and prefix, AWS region, and KMS signing mode. The producer should use its dedicated IAM role through GitHub Actions OIDC and should not receive long-lived AWS credentials.

Configure the consumer with the same S3 bucket and encryption-key settings, along with:

```bash
EVIDENCE_ENGINE_ACCEPTANCE_BACKEND=dynamodb
EVIDENCE_ENGINE_DYNAMODB_TABLE=<acceptance-table-name>
```

Also configure the consumer identity and expected evidence stream according to the application's acceptance-state settings. The consumer role must have permission to read the required S3 object versions and perform the DynamoDB operations used by the acceptance adapter.

The application still requires a locally controlled trust registry. Its `key_id` must match the signing key ARN, and its public key must be the public PEM exported from the asymmetric KMS signing key. The private signing key remains inside AWS KMS.

## Deployment and security boundaries

This Terraform root defines infrastructure and IAM roles; it does not configure the GitHub repository, GitHub Environments, branch protections, or a complete deployment workflow. A deployment workflow must use the matching GitHub Environment and obtain short-lived AWS credentials through OIDC. Do not add long-lived AWS access keys to repository secrets.

The DynamoDB ordered-acceptance mechanism provides atomic digest recording and monotonic checkpoint updates for a consumer and evidence stream. Its rollback protection depends on the integrity and durability of the acceptance table and on the correctness of the consumer and stream identities. It should not be described as protection against every form of rollback, deletion, or privileged AWS account compromise.

Likewise, successful signature verification establishes that the evidence bundle verifies under the configured trust policy; it does not independently establish that the underlying infrastructure was compliant. Evidence provenance, retention enforcement, sanitization, authorization, and human governance remain separate controls requiring their own validation.