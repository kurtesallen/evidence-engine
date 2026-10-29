from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from evidence_engine.aws.reference import BundleReference
from evidence_engine.schema import REQUIRED_ARTIFACTS


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _validate_location(bucket: str, prefix: str) -> tuple[str, str]:
    """Validate an S3 bucket name and normalized object prefix."""
    if not isinstance(bucket, str) or not _BUCKET_RE.fullmatch(bucket):
        raise ValueError("Invalid S3 bucket name")

    if not isinstance(prefix, str):
        raise ValueError("S3 prefix must be a string")

    prefix = prefix.strip("/")

    if not prefix or not _NAME_RE.fullmatch(prefix):
        raise ValueError("Invalid S3 object prefix")

    parts = prefix.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(
            "S3 prefix cannot contain empty or traversal segments"
        )

    return bucket, prefix


def _validate_kms_key_id(kms_key_id: str) -> str:
    """Require an explicit S3 SSE-KMS key identifier."""
    if not isinstance(kms_key_id, str) or not kms_key_id.strip():
        raise ValueError("An explicit S3 SSE-KMS key ID is required")

    return kms_key_id.strip()


class S3BundleStorage:
    """Store and retrieve evidence bundles using S3 SSE-KMS encryption.

    This adapter provides storage integrity checks, not authenticity.
    Always call verify_bundle() after retrieval to validate the manifest
    signature and artifact contents against trusted keys.
    """

    def __init__(
        self,
        client: Any,
        bucket: str,
        kms_key_id: str,
    ) -> None:
        if not callable(getattr(client, "put_object", None)):
            raise TypeError("S3 client must provide put_object")

        if not callable(getattr(client, "get_object", None)):
            raise TypeError("S3 client must provide get_object")

        _validate_location(bucket, "evidence")

        self._client = client
        self._bucket = bucket
        self._kms_key_id = _validate_kms_key_id(kms_key_id)

    @staticmethod
    def _read_file(path: Path) -> bytes:
        """Read a regular file, rejecting symlinks and non-files."""
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Bundle input is not a regular file: {path}")

        return path.read_bytes()

    def _put(self, key: str, content: bytes) -> dict[str, Any]:
        """Upload one object using SSE-KMS and record its content digest."""
        digest = hashlib.sha256(content).hexdigest()

        response = self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=content,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self._kms_key_id,
            Metadata={"sha256": digest},
        )

        return {
            "key": key,
            "sha256": digest,
            "version_id": response.get("VersionId"),
        }

    def upload_bundle(
        self,
        *,
        prefix: str,
        artifacts_root: Path,
        manifest_path: Path,
        signature_path: Path,
    ) -> dict[str, Any]:
        """Upload the manifest, signature, and exact required artifact set."""
        _, prefix = _validate_location(self._bucket, prefix)

        artifacts_root = Path(artifacts_root)

        if not artifacts_root.is_dir() or artifacts_root.is_symlink():
            raise ValueError("artifacts_root must be a regular directory")

        entries = list(artifacts_root.iterdir())

        if any(path.is_symlink() for path in entries):
            raise ValueError("Artifact directory cannot contain symlinks")

        files = {
            path.name: path
            for path in entries
            if path.is_file()
        }

        if set(files) != REQUIRED_ARTIFACTS or len(files) != len(entries):
            raise ValueError(
                "Artifact set mismatch: "
                f"missing={sorted(REQUIRED_ARTIFACTS - set(files))}, "
                f"unexpected={sorted(set(files) - set(REQUIRED_ARTIFACTS))}"
            )

        payloads: dict[str, bytes] = {
            f"{prefix}/manifest.json": self._read_file(Path(manifest_path)),
            f"{prefix}/manifest.sig": self._read_file(Path(signature_path)),
        }

        for name in sorted(REQUIRED_ARTIFACTS):
            payloads[f"{prefix}/artifacts/{name}"] = self._read_file(
                files[name]
            )

        uploaded: list[dict[str, Any]] = []

        for key, content in payloads.items():
            uploaded.append(self._put(key, content))

        # Publish a reference only after all required objects have been
        # uploaded. The reference requires valid digests and immutable
        # S3 version IDs for every object.
        reference = BundleReference.from_upload(
            bucket=self._bucket,
            prefix=prefix,
            objects=uploaded,
        )

        return {
            "bucket": self._bucket,
            "prefix": prefix,
            "objects": uploaded,
            "reference": reference.to_dict(),
        }

    def download_bundle(
        self,
        *,
        prefix: str,
        destination: Path,
        object_versions: dict[str, str] | None = None,
        reference: BundleReference | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Download a complete bundle into staging and publish to a fresh path.

        When ``reference`` is supplied, every object is retrieved by its
        exact S3 version ID, and its SHA-256 digest is checked against the
        reference.

        When ``object_versions`` is supplied directly, it must contain
        every expected object key and a valid version ID for each object.
        This protects against mixing versions from different uploads, but
        does not independently bind the contents to trusted metadata.

        If both arguments are omitted, current S3 object versions are read.
        That mode does not provide immutable-version or reference-digest
        binding. Cryptographic verification is still required after retrieval.
        """
        _, prefix = _validate_location(self._bucket, prefix)
        destination = Path(destination)

        if destination.is_symlink() or (
            destination.exists() and not destination.is_dir()
        ):
            raise ValueError("destination must be a regular directory path")

        expected = [
            f"{prefix}/manifest.json",
            f"{prefix}/manifest.sig",
        ]
        expected.extend(
            f"{prefix}/artifacts/{name}"
            for name in sorted(REQUIRED_ARTIFACTS)
        )
        expected_keys = set(expected)

        validated_reference: BundleReference | None = None
        reference_digests: dict[str, str] = {}

        if reference is not None:
            if object_versions is not None:
                raise ValueError(
                    "Specify reference or object_versions, not both"
                )

            if isinstance(reference, BundleReference):
                validated_reference = BundleReference.from_dict(
                    reference.to_dict()
                )
            elif isinstance(reference, dict):
                validated_reference = BundleReference.from_dict(reference)
            else:
                raise ValueError("Invalid bundle reference")

            if (
                validated_reference.bucket != self._bucket
                or validated_reference.prefix != prefix
            ):
                raise ValueError(
                    "Bundle reference bucket or prefix does not match"
                )

            object_versions = {
                item["key"]: item["version_id"]
                for item in validated_reference.objects
            }
            reference_digests = {
                item["key"]: item["sha256"]
                for item in validated_reference.objects
            }

        # An omitted version map means current-object retrieval.
        # An explicitly supplied map must be complete; partial mappings
        # could otherwise mix objects from different bundle uploads.
        if object_versions is None:
            versions: dict[str, str] = {}
        else:
            if not isinstance(object_versions, dict):
                raise ValueError("object_versions must be a dictionary")

            supplied_keys = set(object_versions)
            unexpected_keys = supplied_keys - expected_keys
            missing_keys = expected_keys - supplied_keys

            if unexpected_keys:
                raise ValueError(
                    "Version index contains unexpected object keys: "
                    f"{sorted(unexpected_keys)}"
                )

            if missing_keys:
                raise ValueError(
                    "object_versions must contain all required object keys; "
                    f"missing={sorted(missing_keys)}"
                )

            for key, version_id in object_versions.items():
                if (
                    not isinstance(version_id, str)
                    or not version_id.strip()
                    or version_id.strip() == "null"
                ):
                    raise ValueError(
                        f"Invalid version ID for S3 object: {key}"
                    )

            versions = object_versions

        # Read and validate all objects before modifying the destination.
        downloaded: list[tuple[str, bytes, str | None]] = []

        for key in expected:
            version_id = versions.get(key)

            request: dict[str, str] = {
                "Bucket": self._bucket,
                "Key": key,
            }

            if version_id is not None:
                request["VersionId"] = version_id

            response = self._client.get_object(**request)

            if validated_reference is not None:
                returned_version = response.get("VersionId")

                if returned_version != version_id:
                    raise ValueError(
                        f"S3 returned an unexpected object version: {key}"
                    )

            body = response.get("Body")

            if body is None or not callable(getattr(body, "read", None)):
                raise ValueError(f"S3 returned an invalid object body: {key}")

            # Close the streaming response to release its resources.
            # A close error must not hide a read error or invalidate bytes
            # that were already read successfully.
            try:
                content = body.read()
            finally:
                close_body = getattr(body, "close", None)

                if callable(close_body):
                    try:
                        close_body()
                    except Exception:
                        pass

            if not isinstance(content, bytes):
                raise ValueError(f"S3 returned non-byte content: {key}")

            actual_digest = hashlib.sha256(content).hexdigest()

            if validated_reference is not None:
                expected_digest = reference_digests[key]

                if actual_digest != expected_digest:
                    raise ValueError(
                        f"Bundle reference digest mismatch: {key}"
                    )

            metadata = response.get("Metadata") or {}
            metadata_digest = metadata.get("sha256")

            if (
                metadata_digest is not None
                and metadata_digest != actual_digest
            ):
                raise ValueError(
                    f"S3 object metadata digest mismatch: {key}"
                )

            downloaded.append((key, content, version_id))

        # Stage the complete bundle next to the destination so publishing
        # can use a same-filesystem rename.
        destination.parent.mkdir(parents=True, exist_ok=True)

        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.staging-",
                dir=destination.parent,
            )
        )

        try:
            for key, content, _version_id in downloaded:
                if key.endswith("/manifest.json"):
                    relative = Path("manifest.json")
                elif key.endswith("/manifest.sig"):
                    relative = Path("manifest.sig")
                else:
                    relative = Path("artifacts") / key.rsplit("/", 1)[-1]

                path = staging / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

            # Never overwrite an existing destination.
            if destination.exists() or destination.is_symlink():
                raise FileExistsError(
                    f"Destination already exists: {destination}"
                )

            staging.rename(destination)

        except Exception:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            raise

        return {
            "bucket": self._bucket,
            "prefix": prefix,
            "objects": [
                {
                    "key": key,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "version_id": version_id,
                }
                for key, content, version_id in downloaded
            ],
        }