"""
AWS KMS asymmetric signing for canonical EvidenceEngine manifests.
"""

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding,
    rsa,
    utils,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256"
KEY_SPEC = "RSA_2048"
KEY_USAGE = "SIGN_VERIFY"
DIGEST_SIZE = hashlib.sha256().digest_size


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

def _validate_key_id(key_id: str) -> None:
    """Require a non-empty KMS key ID, ARN, or alias."""
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("A KMS key ID or ARN is required")


def _validate_message(message: bytes) -> None:
    """Require exact message bytes."""
    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_bytes(
    client: Any,
    key_id: str,
    message: bytes,
) -> bytes:
    """
    Sign the SHA-256 digest of exact message bytes using AWS KMS.

    Returns:
        bytes: Raw RSA-PSS signature from KMS.
    """
    _validate_key_id(key_id)
    _validate_message(message)

    digest = hashlib.sha256(message).digest()

    try:
        response = client.sign(
            KeyId=key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
    except Exception as exc:
        raise ValueError("AWS KMS signing failed") from exc

    if not isinstance(response, dict):
        raise ValueError("AWS KMS returned an invalid signing response")

    signature = response.get("Signature")
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("AWS KMS returned an invalid signature")

    return signature


# ---------------------------------------------------------------------------
# Public Key Retrieval
# ---------------------------------------------------------------------------

def get_public_key_der(client: Any, key_id: str) -> bytes:
    """
    Retrieve and validate an RSA-2048 KMS public key.

    Returns:
        bytes: DER-encoded RSA public key.
    """
    _validate_key_id(key_id)

    try:
        response = client.get_public_key(KeyId=key_id)
    except Exception as exc:
        raise ValueError("AWS KMS public-key retrieval failed") from exc

    if not isinstance(response, dict):
        raise ValueError("AWS KMS returned an invalid public-key response")

    # Validate key metadata
    if response.get("KeySpec") != KEY_SPEC:
        raise ValueError("KMS key must use RSA_2048")

    if response.get("KeyUsage") != KEY_USAGE:
        raise ValueError("KMS key must have KeyUsage SIGN_VERIFY")

    algorithms = response.get("SigningAlgorithms")
    if not isinstance(algorithms, list) or SIGNING_ALGORITHM not in algorithms:
        raise ValueError("KMS key does not support the required algorithm")

    # Extract public key
    public_key = response.get("PublicKey")
    if not isinstance(public_key, bytes) or not public_key:
        raise ValueError("AWS KMS returned an invalid public key")

    # Validate DER structure
    try:
        parsed = serialization.load_der_public_key(public_key)
    except (TypeError, ValueError) as exc:
        raise ValueError("AWS KMS returned malformed public-key data") from exc

    if not isinstance(parsed, rsa.RSAPublicKey):
        raise ValueError("KMS public key is not RSA")

    if parsed.key_size != 2048:
        raise ValueError("KMS public key must be 2048 bits")

    return public_key


# ---------------------------------------------------------------------------
# Local Verification
# ---------------------------------------------------------------------------

def verify_bytes(
    public_key_der: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an RSA-PSS signature locally without AWS credentials.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    if not isinstance(public_key_der, bytes):
        return False
    if not isinstance(message, bytes):
        return False
    if not isinstance(signature, bytes) or not signature:
        return False

    try:
        public_key = serialization.load_der_public_key(public_key_der)

        if not isinstance(public_key, rsa.RSAPublicKey):
            return False
        if public_key.key_size != 2048:
            return False

        public_key.verify(
            signature,
            hashlib.sha256(message).digest(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return True

    except (InvalidSignature, TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Client Factory
# ---------------------------------------------------------------------------

def create_kms_client(region_name: str = "us-east-1") -> Any:
    """
    Create a regional KMS client using the standard AWS credential chain.

    Returns:
        boto3.client: KMS client instance.
    """
    if not isinstance(region_name, str) or not region_name.strip():
        raise ValueError("An AWS region is required")

    try:
        import boto3
    except ImportError as exc:
        raise ValueError(
            "boto3 is required for AWS KMS operations; "
            "install the project's AWS optional dependencies"
        ) from exc

    return boto3.client("kms", region_name=region_name)
