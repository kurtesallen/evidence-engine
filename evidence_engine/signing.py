"""RSA-PSS operations for EvidenceEngine."""

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_ID = "local-dev-2026-01"
RSA_KEY_SIZE = 2048
PSS_SALT_LENGTH = 32


def generate_key_pair(private_path: Path, public_path: Path) -> None:
    """Generate an RSA-2048 key pair and persist it as PEM files."""
    private_path = Path(private_path)
    public_path = Path(public_path)

    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must be different")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    try:
        private_path.chmod(0o600)
    except OSError:
        # Some platforms do not support POSIX permission semantics.
        pass

    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def sign_bytes(private_path: Path, data: bytes) -> bytes:
    """Sign bytes using RSA-PSS with SHA-256 and a 32-byte salt."""
    private_path = Path(private_path)

    key = serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=None,
    )

    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != RSA_KEY_SIZE:
        raise ValueError("Expected an RSA-2048 private key")

    return key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=PSS_SALT_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_bytes(public_path: Path, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature using SHA-256 and a 32-byte salt."""
    public_path = Path(public_path)

    key = serialization.load_pem_public_key(public_path.read_bytes())

    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != RSA_KEY_SIZE:
        raise ValueError("Expected an RSA-2048 public key")

    try:
        key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False

    return True
