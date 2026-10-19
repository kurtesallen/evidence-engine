# EvidenceEngine Protocol v1.1

## Manifest

The manifest uses RFC 8785 JSON Canonicalization Scheme (JCS).

The signature covers the exact canonical manifest bytes stored in
manifest.json. Noncanonical JSON and duplicate object keys are rejected.

Required fields:

- schema_version
- hash_algorithm
- signature_algorithm
- key_id
- provenance
- artifacts

## Cryptography

- Artifact digest: SHA-256
- Signature: RSA-2048 with RSASSA-PSS
- Message digest: SHA-256
- PSS salt length: 32 bytes
- Signature encoding: detached binary signature

## Required sample artifacts

- plan.json
- state.json
- commit.txt
- version.txt

## Provenance

Provenance fields are claims supplied by the producer unless they
are authenticated through a separately governed mechanism.

The local implementation does not establish trusted build provenance.

## Verification

Consumers must:

1. Parse JSON while rejecting duplicate keys.
2. Require canonical JSON serialization.
3. Validate the complete manifest schema.
4. Check the expected key ID.
5. Verify the manifest signature against a trusted public key.
6. Require the exact mandatory artifact set.
7. Recompute each artifact's size and SHA-256 digest.
8. Reject missing, unexpected, or modified artifacts.

## Limitations

This protocol does not independently prove:

- That a trusted workflow produced the evidence.
- That a receipt is fresh or authoritative.
- That an S3 object has effective retention protection.
- That encryption keys remain available.
- That a compliance control passed.