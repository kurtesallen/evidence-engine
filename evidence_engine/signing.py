"""RSA-PSS signing and verification for EvidenceEngine."""

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_key_pair(private_path: Path, public_path: Path) -> None:
    """Generate a local RSA-2048 key pair for development."""
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Restrict the private key file where POSIX permissions are available.
    private_path.write_bytes(private_bytes)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass

    public_path.write_bytes(public_bytes)


def sign_bytes(private_path: Path, data: bytes) -> bytes:
    """Sign exact input bytes using RSA-PSS and SHA-256."""
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Expected an RSA private key")

    if private_key.key_size != 2048:
        raise ValueError("Expected an RSA-2048 private key")

    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )


def verify_bytes(public_path: Path, data: bytes, signature: bytes) -> bool:
    """Verify exact input bytes; return False for invalid signatures."""
    public_key = serialization.load_pem_public_key(
        public_path.read_bytes()
    )

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Expected an RSA public key")

    if public_key.key_size != 2048:
        raise ValueError("Expected an RSA-2048 public key")

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False

    return True