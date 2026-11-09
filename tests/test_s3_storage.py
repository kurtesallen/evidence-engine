
import hashlib
import os
import stat
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


def make_storage(client=None):
    """Create storage with the standard test bucket and KMS key."""
    if client is None:
        client = FakeS3()

    return S3BundleStorage(
        client,
        "evidence-test-bucket",
        "test-kms-key",
    )


def create_directory_symlink(linked_parent: Path, real_parent: Path):
    """Create a directory symlink or skip when the platform disallows it."""
    try:
        linked_parent.symlink_to(
            real_parent,
            target_is_directory=True,
        )
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")


def test_upload_download_round_trip(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

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

    client = FakeS3()
    storage = make_storage(client)

    with pytest.raises(ValueError, match="Artifact set mismatch"):
        storage.upload_bundle(
            prefix="runs/test",
            artifacts_root=artifacts,
            manifest_path=manifest,
            signature_path=signature,
        )

    assert client.put_calls == []


def test_upload_rejects_symlinked_artifact_parent(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    linked_parent = tmp_path / "linked-artifact-parent"
    create_directory_symlink(linked_parent, tmp_path)

    linked_artifacts = linked_parent / artifacts.name

    with pytest.raises(
        ValueError,
        match="Filesystem path cannot contain symlinks",
    ):
        storage.upload_bundle(
            prefix="runs/symlinked-artifacts",
            artifacts_root=linked_artifacts,
            manifest_path=manifest,
            signature_path=signature,
        )

    assert client.put_calls == []


def test_upload_rejects_symlinked_manifest_parent(bundle, tmp_path):
    artifacts, _manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    real_parent = tmp_path / "real-manifest-parent"
    real_parent.mkdir()

    real_manifest = real_parent / "manifest.json"
    real_manifest.write_bytes(b'{"test":"manifest"}')

    linked_parent = tmp_path / "linked-manifest-parent"
    create_directory_symlink(linked_parent, real_parent)

    linked_manifest = linked_parent / "manifest.json"

    with pytest.raises(
        ValueError,
        match="Filesystem path cannot contain symlinks",
    ):
        storage.upload_bundle(
            prefix="runs/symlinked-manifest",
            artifacts_root=artifacts,
            manifest_path=linked_manifest,
            signature_path=signature,
        )

    assert client.put_calls == []


def test_upload_rejects_symlinked_signature_parent(bundle, tmp_path):
    artifacts, manifest, _signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    real_parent = tmp_path / "real-signature-parent"
    real_parent.mkdir()

    real_signature = real_parent / "manifest.sig"
    real_signature.write_bytes(b"test-signature")

    linked_parent = tmp_path / "linked-signature-parent"
    create_directory_symlink(linked_parent, real_parent)

    linked_signature = linked_parent / "manifest.sig"

    with pytest.raises(
        ValueError,
        match="Filesystem path cannot contain symlinks",
    ):
        storage.upload_bundle(
            prefix="runs/symlinked-signature",
            artifacts_root=artifacts,
            manifest_path=manifest,
            signature_path=linked_signature,
        )

    assert client.put_calls == []


def test_download_rejects_digest_metadata_mismatch(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

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
    storage = make_storage()

    with pytest.raises(ValueError, match="prefix"):
        storage.download_bundle(
            prefix=prefix,
            destination=Path("unused"),
        )


def test_requires_explicit_kms_key():
    with pytest.raises(ValueError, match="SSE-KMS key ID"):
        S3BundleStorage(
            FakeS3(),
            "evidence-test-bucket",
            "",
        )


def test_metadata_digest_is_sha256(bundle):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

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
    storage = make_storage(client)

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
    storage = make_storage(client)

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
    storage = make_storage()

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
    storage = make_storage()

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
    storage = make_storage(client)

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
    storage = make_storage()

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
    storage = make_storage()

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
    storage = make_storage()

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
    storage = make_storage()

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
    storage = make_storage()

    with pytest.raises(ValueError, match="prefix"):
        storage.download_bundle(
            prefix="runs//unsafe",
            destination=tmp_path / "unsafe-download",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission modes")
def test_download_creates_private_files_and_directories(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    storage.upload_bundle(
        prefix="runs/private-download",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    destination = tmp_path / "private-download"

    storage.download_bundle(
        prefix="runs/private-download",
        destination=destination,
    )

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700

    downloaded_artifacts = destination / "artifacts"
    assert stat.S_IMODE(downloaded_artifacts.stat().st_mode) == 0o700

    private_files = [
        destination / "manifest.json",
        destination / "manifest.sig",
        *(
            downloaded_artifacts / name
            for name in REQUIRED_ARTIFACTS
        ),
    ]

    for path in private_files:
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_download_rejects_symlinked_destination_parent(bundle, tmp_path):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    storage.upload_bundle(
        prefix="runs/symlink-parent",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()

    linked_parent = tmp_path / "linked-parent"
    create_directory_symlink(linked_parent, real_parent)

    destination = linked_parent / "download"

    with pytest.raises(ValueError, match="cannot contain symlinks"):
        storage.download_bundle(
            prefix="runs/symlink-parent",
            destination=destination,
        )

    assert not (real_parent / "download").exists()
    assert not list(real_parent.glob(".download.staging-*"))


def test_download_cleans_staging_when_publication_fails(
    bundle, tmp_path, monkeypatch
):
    artifacts, manifest, signature = bundle
    client = FakeS3()
    storage = make_storage(client)

    storage.upload_bundle(
        prefix="runs/failed-download",
        artifacts_root=artifacts,
        manifest_path=manifest,
        signature_path=signature,
    )

    destination = tmp_path / "failed-download"
    original_rename = Path.rename

    def fail_staging_publication(path, target):
        if path.name.startswith(".failed-download.staging-"):
            raise OSError("simulated publication failure")
        return original_rename(path, target)

    monkeypatch.setattr(Path, "rename", fail_staging_publication)

    with pytest.raises(OSError, match="simulated publication failure"):
        storage.download_bundle(
            prefix="runs/failed-download",
            destination=destination,
        )

    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-download.staging-*"))
