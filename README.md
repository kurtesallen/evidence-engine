# EvidenceEngine

A teaching implementation of Evidence as Code.

## Current capabilities

- Sample evidence collection
- SHA-256 artifact hashing
- Deterministic JSON serialization for the prototype
- RSA-2048 / RSASSA-PSS manifest signing
- Independent signature and digest verification
- Artifact and manifest tampering tests

## Local setup

    python -m venv .venv
    python -m pip install -e ".[dev]"

## Generate evidence

    python -m evidence_engine.collect

## Seal evidence

    python -m evidence_engine.verify seal \
      --artifacts evidence/artifacts \
      --output evidence/sealed \
      --private-key keys/private.pem

## Run tests

    python -m pytest -v

This is a learning prototype, not a production compliance system.