import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from evidence_engine import kms_signing


KEY_ID = "arn:aws:kms:us-east-1:111122223333:key/test-key"


class FakeKms:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.last_sign_request = None

    def sign(self, **kwargs):
        self.last_sign_request = kwargs
        signature = self.private_key.sign(
            kwargs["Message"],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return {"Signature": signature}

    def get_public_key(self, **kwargs):
        public_key = self.private_key.public_key()
        return {
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PSS_SHA_256"],
            "PublicKey": public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }


def test_signs_sha256_digest_with_expected_parameters():
    client = FakeKms()
    message = b'{"schema_version":"1.1"}'

    signature = kms_signing.sign_bytes(client, KEY_ID, message)

    assert signature
    assert client.last_sign_request == {
        "KeyId": KEY_ID,
        "Message": hashlib.sha256(message).digest(),
        "MessageType": "DIGEST",
        "SigningAlgorithm": "RSASSA_PSS_SHA_256",
    }


def test_signature_verifies_with_exported_public_key():
    client = FakeKms()
    message = b"canonical manifest"

    signature = kms_signing.sign_bytes(client, KEY_ID, message)
    public_key = kms_signing.get_public_key_der(client, KEY_ID)

    assert kms_signing.verify_bytes(public_key, message, signature)


def test_modified_manifest_fails_verification():
    client = FakeKms()
    signature = kms_signing.sign_bytes(client, KEY_ID, b"original")
    public_key = kms_signing.get_public_key_der(client, KEY_ID)

    assert not kms_signing.verify_bytes(
        public_key, b"modified", signature
    )


def test_modified_signature_fails_verification():
    client = FakeKms()
    message = b"manifest"
    signature = kms_signing.sign_bytes(client, KEY_ID, message)
    public_key = kms_signing.get_public_key_der(client, KEY_ID)

    corrupted = bytes([signature[0] ^ 1]) + signature[1:]

    assert not kms_signing.verify_bytes(public_key, message, corrupted)


def test_empty_key_id_is_rejected():
    with pytest.raises(ValueError, match="key ID"):
        kms_signing.sign_bytes(FakeKms(), "", b"manifest")


def test_kms_signing_failure_is_reported():
    class FailingKms:
        def sign(self, **kwargs):
            raise RuntimeError("simulated AWS failure")

    with pytest.raises(ValueError, match="KMS signing failed"):
        kms_signing.sign_bytes(FailingKms(), KEY_ID, b"manifest")


def test_unsupported_key_spec_is_rejected():
    class WrongKey(FakeKms):
        def get_public_key(self, **kwargs):
            result = super().get_public_key(**kwargs)
            result["KeySpec"] = "ECC_NIST_P256"
            return result

    with pytest.raises(ValueError, match="RSA_2048"):
        kms_signing.get_public_key_der(WrongKey(), KEY_ID)


def test_wrong_key_usage_is_rejected():
    class WrongUsage(FakeKms):
        def get_public_key(self, **kwargs):
            result = super().get_public_key(**kwargs)
            result["KeyUsage"] = "ENCRYPT_DECRYPT"
            return result

    with pytest.raises(ValueError, match="SIGN_VERIFY"):
        kms_signing.get_public_key_der(WrongUsage(), KEY_ID)


def test_missing_signing_algorithm_is_rejected():
    class WrongAlgorithm(FakeKms):
        def get_public_key(self, **kwargs):
            result = super().get_public_key(**kwargs)
            result["SigningAlgorithms"] = ["RSASSA_PKCS1_V1_5_SHA_256"]
            return result

    with pytest.raises(ValueError, match="required algorithm"):
        kms_signing.get_public_key_der(WrongAlgorithm(), KEY_ID)


def test_invalid_public_key_is_rejected():
    class MalformedKey(FakeKms):
        def get_public_key(self, **kwargs):
            result = super().get_public_key(**kwargs)
            result["PublicKey"] = b"not a DER key"
            return result

    with pytest.raises(ValueError, match="malformed"):
        kms_signing.get_public_key_der(MalformedKey(), KEY_ID)