from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from evidence_engine.schema import REQUIRED_ARTIFACTS


_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SCHEMA_VERSION = 1
_OBJECT_FIELDS = {"key", "sha256", "version_id"}


def _validate_bucket(bucket: Any) -> str:
    """Validate the supported S3 bucket-name syntax."""
    if (
        not isinstance(bucket, str)
        or not _BUCKET_RE.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        raise ValueError("Invalid bundle reference bucket")

    return bucket


def _validate_prefix(prefix: Any) -> str:
    """Require a canonical prefix without empty or traversal segments."""
    if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
        raise ValueError("Invalid bundle reference prefix")

    if prefix.startswith("/") or prefix.endswith("/"):
        raise ValueError("Invalid bundle reference prefix")

    if any(part in {"", ".", ".."} for part in prefix.split("/")):
        raise ValueError("Invalid bundle reference prefix")

    return prefix


def _expected_keys(prefix: str) -> set[str]:
    return {
        f"{prefix}/manifest.json",
        f"{prefix}/manifest.sig",
        *(
            f"{prefix}/artifacts/{name}"
            for name in REQUIRED_ARTIFACTS
        ),
    }


@dataclass(frozen=True)
class BundleReference:
    """Reference to the exact versions of all required S3 bundle objects.

    The objects collection and its individual mappings are immutable.
    Use to_dict() to obtain a mutable serialization suitable for JSON.
    """

    bucket: str
    prefix: str
    manifest_key: str
    signature_key: str
    manifest_sha256: str
    objects: tuple[Mapping[str, str], ...]

    @classmethod
    def from_upload(
        cls,
        *,
        bucket: str,
        prefix: str,
        objects: list[dict[str, Any]],
    ) -> BundleReference:
        """Build a validated reference from successful upload results."""
        bucket = _validate_bucket(bucket)
        prefix = _validate_prefix(prefix)

        if not isinstance(objects, list):
            raise ValueError("Uploaded objects must be a list")

        by_key: dict[str, dict[str, Any]] = {}

        for item in objects:
            if not isinstance(item, dict) or set(item) != _OBJECT_FIELDS:
                raise ValueError("Invalid uploaded object entry")

            key = item["key"]
            if not isinstance(key, str):
                raise ValueError(
                    "Uploaded objects do not match the required bundle"
                )

            if key in by_key:
                raise ValueError(
                    "Uploaded objects do not match the required bundle"
                )

            by_key[key] = item

        expected = _expected_keys(prefix)

        if set(by_key) != expected:
            raise ValueError(
                "Uploaded objects do not match the required bundle"
            )

        normalized: list[Mapping[str, str]] = []

        for key in sorted(expected):
            item = by_key[key]
            version_id = item["version_id"]
            digest = item["sha256"]

            if (
                not isinstance(version_id, str)
                or not version_id
                or version_id != version_id.strip()
                or version_id == "null"
            ):
                raise ValueError(
                    f"Missing immutable S3 VersionId for {key}"
                )

            if (
                not isinstance(digest, str)
                or not _DIGEST_RE.fullmatch(digest)
            ):
                raise ValueError(f"Invalid SHA-256 digest for {key}")

            normalized.append(
                MappingProxyType(
                    {
                        "key": key,
                        "sha256": digest,
                        "version_id": version_id,
                    }
                )
            )

        manifest_key = f"{prefix}/manifest.json"
        signature_key = f"{prefix}/manifest.sig"

        digest_by_key = {
            item["key"]: item["sha256"] for item in normalized
        }

        return cls(
            bucket=bucket,
            prefix=prefix,
            manifest_key=manifest_key,
            signature_key=signature_key,
            manifest_sha256=digest_by_key[manifest_key],
            objects=tuple(normalized),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible copy of the reference."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "manifest_key": self.manifest_key,
            "signature_key": self.signature_key,
            "manifest_sha256": self.manifest_sha256,
            "objects": [dict(item) for item in self.objects],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BundleReference:
        """Deserialize and validate an untrusted bundle reference."""
        if not isinstance(value, dict):
            raise ValueError("Bundle reference must be an object")

        expected_fields = {
            "schema_version",
            "bucket",
            "prefix",
            "manifest_key",
            "signature_key",
            "manifest_sha256",
            "objects",
        }

        if set(value) != expected_fields:
            raise ValueError("Invalid bundle reference fields")

        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != _SCHEMA_VERSION
        ):
            raise ValueError("Unsupported bundle reference schema version")

        bucket = _validate_bucket(value["bucket"])
        prefix = _validate_prefix(value["prefix"])

        objects = value["objects"]
        if not isinstance(objects, list):
            raise ValueError("Bundle reference objects must be a list")

        for item in objects:
            if not isinstance(item, dict) or set(item) != _OBJECT_FIELDS:
                raise ValueError("Invalid bundle reference object entry")

        reference = cls.from_upload(
            bucket=bucket,
            prefix=prefix,
            objects=objects,
        )

        if value["manifest_key"] != reference.manifest_key:
            raise ValueError("Invalid manifest key in bundle reference")

        if value["signature_key"] != reference.signature_key:
            raise ValueError("Invalid signature key in bundle reference")

        if value["manifest_sha256"] != reference.manifest_sha256:
            raise ValueError(
                "Manifest digest does not match object reference"
            )

        return reference