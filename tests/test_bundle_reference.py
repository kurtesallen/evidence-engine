import copy

import pytest

from evidence_engine.aws.reference import BundleReference
from evidence_engine.schema import REQUIRED_ARTIFACTS


@pytest.fixture
def uploaded_objects():
    prefix = "runs/test-123"
    keys = [
        f"{prefix}/manifest.json",
        f"{prefix}/manifest.sig",
        *(
            f"{prefix}/artifacts/{name}"
            for name in sorted(REQUIRED_ARTIFACTS)
        ),
    ]

    return [
        {
            "key": key,
            "sha256": "a" * 64,
            "version_id": f"version-{index}",
        }
        for index, key in enumerate(keys, start=1)
    ]


def test_reference_round_trip(uploaded_objects):
    reference = BundleReference.from_upload(
        bucket="evidence-test-bucket",
        prefix="runs/test-123",
        objects=uploaded_objects,
    )

    restored = BundleReference.from_dict(reference.to_dict())

    assert restored == reference
    assert restored.manifest_key == "runs/test-123/manifest.json"
    assert restored.signature_key == "runs/test-123/manifest.sig"
    assert restored.manifest_sha256 == "a" * 64


def test_reference_rejects_missing_object(uploaded_objects):
    with pytest.raises(ValueError, match="required bundle"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=uploaded_objects[:-1],
        )


@pytest.mark.parametrize("version_id", [None, "", "  ", "null"])
def test_reference_rejects_missing_or_mutable_version(
    uploaded_objects, version_id
):
    objects = copy.deepcopy(uploaded_objects)
    objects[0]["version_id"] = version_id

    with pytest.raises(ValueError, match="VersionId"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=objects,
        )


def test_reference_rejects_invalid_digest(uploaded_objects):
    objects = copy.deepcopy(uploaded_objects)
    objects[0]["sha256"] = "not-a-digest"

    with pytest.raises(ValueError, match="SHA-256"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=objects,
        )


def test_reference_rejects_unexpected_keys(uploaded_objects):
    objects = copy.deepcopy(uploaded_objects)
    objects[0]["key"] = "other-prefix/manifest.json"

    with pytest.raises(ValueError, match="required bundle"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=objects,
        )


def test_reference_rejects_modified_manifest_digest(uploaded_objects):
    reference = BundleReference.from_upload(
        bucket="evidence-test-bucket",
        prefix="runs/test-123",
        objects=uploaded_objects,
    )
    serialized = reference.to_dict()
    serialized["manifest_sha256"] = "b" * 64

    with pytest.raises(ValueError, match="Manifest digest"):
        BundleReference.from_dict(serialized)


def test_reference_rejects_path_traversal(uploaded_objects):
    reference = BundleReference.from_upload(
        bucket="evidence-test-bucket",
        prefix="runs/test-123",
        objects=uploaded_objects,
    ).to_dict()
    reference["prefix"] = "../escape"

    with pytest.raises(ValueError, match="prefix"):
        BundleReference.from_dict(reference)

@pytest.mark.parametrize(
    "bucket",
    [
        "",
        "Invalid_Bucket",
        "evidence..bucket",
        "evidence-.bucket",
        "evidence-bucket-",
    ],
)
def test_reference_rejects_invalid_bucket(uploaded_objects, bucket):
    with pytest.raises(ValueError, match="bucket"):
        BundleReference.from_upload(
            bucket=bucket,
            prefix="runs/test-123",
            objects=uploaded_objects,
        )


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "/runs/test",
        "runs/test/",
        "runs//test",
        "runs/../escape",
        "runs/./test",
        "runs\\test",
        "runs/?test",
    ],
)
def test_reference_rejects_invalid_prefix(uploaded_objects, prefix):
    with pytest.raises(ValueError, match="prefix"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix=prefix,
            objects=uploaded_objects,
        )


@pytest.mark.parametrize("version_id", [" null ", " null", "null "])
def test_reference_rejects_padded_null_version(
    uploaded_objects, version_id
):
    objects = copy.deepcopy(uploaded_objects)
    objects[0]["version_id"] = version_id

    with pytest.raises(ValueError, match="VersionId"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=objects,
        )


def test_reference_rejects_malformed_uploaded_object():
    with pytest.raises(ValueError, match="object entry"):
        BundleReference.from_upload(
            bucket="evidence-test-bucket",
            prefix="runs/test-123",
            objects=[None],
        )


def test_reference_object_entries_are_immutable(uploaded_objects):
    reference = BundleReference.from_upload(
        bucket="evidence-test-bucket",
        prefix="runs/test-123",
        objects=uploaded_objects,
    )

    with pytest.raises(TypeError):
        reference.objects[0]["key"] = "runs/other/manifest.json"