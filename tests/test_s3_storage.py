import hashlib
from io import BytesIO
from pathlib import Path

import pytest

from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.schema import REQUIRED_ARTIFACTS


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.put_calls = []
        self.get_calls = []
        self.version_counter = 0

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        self.version_counter += 1

        key = (kwargs["Bucket"], kwargs["Key"])
        version_id = f"version-{self.version_counter}"

        version = {
            "Body": kwargs["Body"],
            "Metadata": dict(kwargs["Metadata"]),
            "VersionId": version_id,
        }

        self.objects.setdefault(key, []).append(version)
        return {"VersionId": version_id}

    def get_object(self, **kwargs):
        self.get_calls.append(kwargs)

        key = (kwargs["Bucket"], kwargs["Key"])
        versions = self.objects[key]
        requested_version = kwargs.get("VersionId")

        if requested_version is None:
            obj = versions[-1]
        else:
            obj = next(
                (
                    item
                    for item in versions
                    if item["VersionId"] == requested_version
                ),
                None,
            )

            if obj is None:
                raise ValueError(
                    f"Unknown version: {requested_version}"
                )

        return {
            "Body": BytesIO(obj["Body"]),
            "Metadata": dict(obj["Metadata"]),
            "VersionId": obj["VersionId"],
        }


@pytest.fixture
def bundle(tmp_path):
    artifacts = tmp_path / "source-artifacts"
    artifacts.mkdir()

    for name in REQUIRED_ARTIFACTS:
        (artifacts / name).write_bytes(f"test:{name}\n".encode())

    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b'{"test":"manifest"}')

    signature = tmp_path / "manifest.sig"
    signature.write_bytes(b"test-signature")

    return artifacts, manifest, signature


def test_upload_download_round_trip(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/test-123",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    assert len(uploaded["objects"]) == len(REQUIRED_ARTIFACTS) + 2
    assert all(
        call["ServerSideEncryption"] == "aws:kms"
        and call["SSEKMSKeyId"] == "test-kms-key"
        for call in client.put_calls
    )

    destination = tmp_path / "downloaded"
    result = storage.download_bundle(
        prefix="runs/test-123",
        destination=destination,
    )

    assert len(result["objects"]) == len(REQUIRED_ARTIFACTS) + 2
    assert (destination / "manifest.json").read_bytes() == (
        manifest.read_bytes()
    )
    assert (destination / "manifest.sig").read_bytes() == (
        signature.read_bytes()
    )

    for name in REQUIRED_ARTIFACTS:
        assert (
            destination / "artifacts" / name
        ).read_bytes() == (artifacts / name).read_bytes()


def test_upload_rejects_missing_required_artifact(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "plan.json").write_bytes(b"plan")

    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"{}")

    signature = tmp_path / "manifest.sig"
    signature.write_bytes(b"sig")

    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    with pytest.raises(ValueError, match="Artifact set mismatch"):
        storage.upload_bundle(
            prefix="runs/test",
            artifacts_root=artifacts,
            manifest_path=manifest,
            signature_path=signature,
        )


def test_download_rejects_digest_metadata_mismatch(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    storage.upload_bundle(
        prefix="runs/test",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    key = ("evidence-test-bucket", "runs/test/manifest.json")
    client.objects[key][-1]["Metadata"]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="metadata digest mismatch"):
        storage.download_bundle(
            prefix="runs/test",
            destination=tmp_path / "downloaded",
        )


@pytest.mark.parametrize(
    "prefix",
    ["", "../escape", "runs/../escape"],
)
def test_rejects_unsafe_prefix(prefix):
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    with pytest.raises(ValueError, match="prefix"):
        storage.download_bundle(
            prefix=prefix,
            destination=Path("unused"),
        )


def test_requires_explicit_kms_key():
    with pytest.raises(ValueError, match="SSE-KMS key ID"):
        S3BundleStorage(
            FakeS3(), "evidence-test-bucket", ""
        )


def test_metadata_digest_is_sha256(bundle):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    storage.upload_bundle(
        prefix="runs/test",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    stored = client.objects[
        ("evidence-test-bucket", "runs/test/manifest.json")
    ][-1]

    assert stored["Metadata"]["sha256"] == hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()


def test_download_uses_requested_object_versions(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/versioned",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    versions = {
        item["key"]: item["version_id"]
        for item in uploaded["objects"]
    }

    # Create a newer version of the manifest with different content.
    newer_body = b'{"newer":"version"}'
    client.put_object(
        Bucket="evidence-test-bucket",
        Key="runs/versioned/manifest.json",
        Body=newer_body,
        Metadata={
            "sha256": hashlib.sha256(newer_body).hexdigest()
        },
    )

    destination = tmp_path / "versioned-download"
    storage.download_bundle(
        prefix="runs/versioned",
        destination=destination,
        object_versions=versions,
    )

    assert (destination / "manifest.json").read_bytes() == (
        manifest.read_bytes()
    )
    assert any(
        call.get("VersionId")
        == versions["runs/versioned/manifest.json"]
        for call in client.get_calls
    )


def test_download_does_not_overwrite_existing_destination(
    bundle, tmp_path
):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    storage.upload_bundle(
        prefix="runs/no-overwrite",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    destination = tmp_path / "already-published"
    destination.mkdir()

    marker = destination / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        storage.download_bundle(
            prefix="runs/no-overwrite",
            destination=destination,
        )

    assert marker.read_text(encoding="utf-8") == "keep"
    assert not list(
        tmp_path.glob(".already-published.staging-*")
    )


def test_download_rejects_unknown_version_key(bundle, tmp_path):
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    with pytest.raises(ValueError, match="unexpected object keys"):
        storage.download_bundle(
            prefix="runs/test",
            destination=tmp_path / "downloaded",
            object_versions={
                "other/prefix/manifest.json": "version-1"
            },
        )


def test_upload_returns_validated_bundle_reference(bundle):
    artifacts, manifest, signature = bundle
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/reference",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    reference = uploaded["reference"]

    assert reference["bucket"] == "evidence-test-bucket"
    assert reference["prefix"] == "runs/reference"
    assert len(reference["objects"]) == len(REQUIRED_ARTIFACTS) + 2
    assert all(
        item["version_id"] and item["version_id"] != "null"
        for item in reference["objects"]
    )


def test_download_using_reference_retrieves_exact_versions(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = S3BundleStorage(
        client, "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/reference-versioned",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    reference = uploaded["reference"]

    # Introduce a newer manifest version after publication.
    newer_body = b'{"newer":"version"}'
    client.put_object(
        Bucket="evidence-test-bucket",
        Key="runs/reference-versioned/manifest.json",
        Body=newer_body,
        Metadata={
            "sha256": hashlib.sha256(newer_body).hexdigest()
        },
    )

    destination = tmp_path / "reference-download"
    storage.download_bundle(
        prefix="runs/reference-versioned",
        destination=destination,
        reference=reference,
    )

    assert (destination / "manifest.json").read_bytes() == (
        manifest.read_bytes()
    )


def test_download_reference_rejects_wrong_prefix(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/reference",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    with pytest.raises(ValueError, match="bucket or prefix"):
        storage.download_bundle(
            prefix="runs/other",
            destination=tmp_path / "wrong-prefix",
            reference=uploaded["reference"],
        )


def test_download_reference_rejects_modified_digest(bundle, tmp_path):
    import copy

    artifacts, manifest, signature = bundle
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/reference-digest",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    reference = copy.deepcopy(uploaded["reference"])
    reference["manifest_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="Manifest digest"):
        storage.download_bundle(
            prefix="runs/reference-digest",
            destination=tmp_path / "bad-reference",
            reference=reference,
        )

def test_download_rejects_partial_object_versions(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/partial-versions",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    versions = {
        item["key"]: item["version_id"]
        for item in uploaded["objects"]
    }
    versions.pop(next(iter(versions)))

    with pytest.raises(ValueError, match="all required object keys"):
        storage.download_bundle(
            prefix="runs/partial-versions",
            destination=tmp_path / "partial-download",
            object_versions=versions,
        )


@pytest.mark.parametrize(
    "invalid_version",
    [None, "", " ", "null", " null "],
)
def test_download_rejects_invalid_version_ids(
    bundle, tmp_path, invalid_version
):
    artifacts, manifest, signature = bundle
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    uploaded = storage.upload_bundle(
        prefix="runs/invalid-versions",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    versions = {
        item["key"]: item["version_id"]
        for item in uploaded["objects"]
    }
    versions["runs/invalid-versions/manifest.json"] = invalid_version

    with pytest.raises(ValueError, match="Invalid version ID"):
        storage.download_bundle(
            prefix="runs/invalid-versions",
            destination=tmp_path / "invalid-download",
            object_versions=versions,
        )

    assert not (tmp_path / "invalid-download").exists()


def test_download_rejects_repeated_separator_prefix(tmp_path):
    storage = S3BundleStorage(
        FakeS3(), "evidence-test-bucket", "test-kms-key"
    )

    with pytest.raises(ValueError, match="prefix"):
        storage.download_bundle(
            prefix="runs//unsafe",
            destination=tmp_path / "unsafe-download",
        )