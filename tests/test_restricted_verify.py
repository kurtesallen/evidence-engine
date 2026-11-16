"""Independent verification tests for experimental restricted evidence."""
import hashlib
import json
from pathlib import Path
import pytest
from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.restricted_contract import PROFILE_20, PROFILE_21
from evidence_engine.restricted_verify import verify_restricted_bundle
from evidence_engine.signing import KEY_ID, generate_key_pair, sign_bytes
from evidence_engine.verify import verify_bundle
PROFILES = (PROFILE_20, PROFILE_21)

def restricted_document(name, profile, terraform_version="1.9.0"):
    document = {
        "evidence_profile": profile,
        "format_version": "1.0",
        "terraform_version": terraform_version,
        "resource_details": "omitted",
    }
    if name == "plan.json":
        if profile == PROFILE_20:
            document["change_details"] = "omitted"
        else:
            document["change_summary"] = {
                "scope": "resource_changes",
                "creates": 1,
                "updates": 0,
                "deletes": 0,
                "replacements": 0,
                "reads": 0,
                "no_ops": 0,
                "total": 1,
            }
    return document

@pytest.fixture(params=PROFILES)

def restricted_bundle(tmp_path, request):
    profile = request.param
    project = tmp_path / "project"
    artifacts = project / "artifacts"
    bundle = project / "bundle"
    config = project / "config"
    keys = project / "keys"
    for directory in (artifacts, bundle, config, keys):
        directory.mkdir(parents=True)
    private_key = keys / "private.pem"
    public_key = keys / "public.pem"
    generate_key_pair(private_key, public_key)
    registry_path = config / "trust_registry.json"
    registry_path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "keys": [{
                "key_id": KEY_ID,
                "public_key": "../keys/public.pem",
                "status": "active",
                "allowed_sources": ["github-actions-claimed"],
            }],
        }),
        encoding="utf-8",
    )
    contents = {
        name: canonical_json_bytes(restricted_document(name, profile))
        for name in ("plan.json", "state.json")
    }
    contents["commit.txt"] = b"a" * 40 + b"\n"
    contents["version.txt"] = b"1.9.0\n"
    for name, content in contents.items():
        (artifacts / name).write_bytes(content)
    rule_version = "2.0" if profile == PROFILE_20 else "2.1"
    entries = []
    for name, content in sorted(contents.items()):
        restricted = name in {"plan.json", "state.json"}
        entries.append({
            "name": name,
            "size_bytes": len(content),
            "representation": "sanitized" if restricted else "raw",
            "sanitization_rule_version": (
                rule_version if restricted else None
            ),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    manifest = {
        "schema_version": "1.4",
        "evidence_profile": profile,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": KEY_ID,
        "provenance": {
            "repository": "example/restricted-evidence",
            "commit_sha": "a" * 40,
            "workflow_run_id": "12345",
            "terraform_version": "1.9.0",
            "provider_lock_sha256": "",
            "source": "github-actions-claimed",
            "ref": "refs/heads/main",
            "workflow_ref": (
                "example/restricted-evidence/"
                ".github/workflows/evidence.yml@refs/heads/main"
            ),
            "run_number": "10",
            "run_attempt": "1",
            "stream_id": "restricted-evidence-test",
        },
        "artifacts": entries,
    }
    manifest_path = bundle / "manifest.json"
    signature_path = bundle / "manifest.sig"
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)
    signature_path.write_bytes(sign_bytes(private_key, manifest_bytes))
    return {
        "profile": profile,
        "artifacts": artifacts,
        "manifest": manifest_path,
        "signature": signature_path,
        "trust_registry": registry_path,
        "private_key": private_key,
        "key_id": KEY_ID,
    }

def verify(bundle, allowed_profiles):
    return verify_restricted_bundle(
        bundle["artifacts"],
        bundle["manifest"],
        bundle["signature"],
        bundle["trust_registry"],
        bundle["key_id"],
        allowed_profiles=allowed_profiles,
    )

def resign(bundle, manifest):
    content = canonical_json_bytes(manifest)
    bundle["manifest"].write_bytes(content)
    bundle["signature"].write_bytes(
        sign_bytes(bundle["private_key"], content)
    )

def update_artifact_and_resign(bundle, name, content):
    (bundle["artifacts"] / name).write_bytes(content)
    manifest = json.loads(bundle["manifest"].read_bytes())
    for entry in manifest["artifacts"]:
        if entry["name"] == name:
            entry["size_bytes"] = len(content)
            entry["sha256"] = hashlib.sha256(content).hexdigest()
    resign(bundle, manifest)

def test_authorized_signed_restricted_bundle_verifies(restricted_bundle):
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is True

def test_empty_authorization_rejects(restricted_bundle):
    assert verify(restricted_bundle, frozenset()) is False

def test_other_profile_authorization_rejects(restricted_bundle):
    other = (
        PROFILE_21
        if restricted_bundle["profile"] == PROFILE_20
        else PROFILE_20
    )
    assert verify(restricted_bundle, frozenset({other})) is False

def test_invalid_authorization_type_rejects(restricted_bundle):
    assert verify(restricted_bundle, "all") is False

def test_invalid_signature_rejects(restricted_bundle):
    restricted_bundle["signature"].write_bytes(b"invalid-signature")
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

@pytest.mark.parametrize("status", ["revoked", "retired"])

def test_inactive_signing_key_rejects(restricted_bundle, status):
    path = restricted_bundle["trust_registry"]
    registry = json.loads(path.read_text(encoding="utf-8"))
    registry["keys"][0]["status"] = status
    path.write_text(json.dumps(registry), encoding="utf-8")
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_unauthorized_signing_source_rejects(restricted_bundle):
    path = restricted_bundle["trust_registry"]
    registry = json.loads(path.read_text(encoding="utf-8"))
    registry["keys"][0]["allowed_sources"] = ["local-claimed"]
    path.write_text(json.dumps(registry), encoding="utf-8")
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_modified_artifact_rejects(restricted_bundle):
    (restricted_bundle["artifacts"] / "plan.json").write_bytes(
        b"tampered"
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_unexpected_artifact_rejects(restricted_bundle):
    (restricted_bundle["artifacts"] / "unexpected.txt").write_bytes(
        b"extra"
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_signed_mismatched_document_profile_rejects(restricted_bundle):
    other = (
        PROFILE_21
        if restricted_bundle["profile"] == PROFILE_20
        else PROFILE_20
    )
    document = restricted_document("state.json", other)
    update_artifact_and_resign(
        restricted_bundle,
        "state.json",
        canonical_json_bytes(document),
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_signed_noncanonical_document_rejects(restricted_bundle):
    document = restricted_document(
        "state.json",
        restricted_bundle["profile"],
    )
    content = json.dumps(document, indent=2).encode("utf-8")
    update_artifact_and_resign(
        restricted_bundle,
        "state.json",
        content,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_signed_terraform_version_mismatch_rejects(restricted_bundle):
    document = restricted_document(
        "state.json",
        restricted_bundle["profile"],
        terraform_version="1.10.0",
    )
    update_artifact_and_resign(
        restricted_bundle,
        "state.json",
        canonical_json_bytes(document),
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_signed_invalid_restricted_content_rejects(restricted_bundle):
    document = restricted_document(
        "state.json",
        restricted_bundle["profile"],
    )
    document["resource_details"] = {
        "secret": "must-not-appear"
    }
    update_artifact_and_resign(
        restricted_bundle,
        "state.json",
        canonical_json_bytes(document),
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

def test_production_verifier_still_rejects_v14(restricted_bundle):
    assert verify_bundle(
        restricted_bundle["artifacts"],
        restricted_bundle["manifest"],
        restricted_bundle["signature"],
        restricted_bundle["trust_registry"],
        restricted_bundle["key_id"],
    ) is False

def test_restricted_artifacts_are_read_once(
    restricted_bundle,
    monkeypatch,
):

    """Open each artifact once for hashing and restricted validation."""
    import evidence_engine.restricted_verify as restricted_verify
    # Preserve established POSIX capability while os.open is patched.
    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")
    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: True,
    )
    import evidence_engine.trust as trust_module
    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")
    # The os.open wrapper below is not registered in os.supports_dir_fd.
    # Preserve the established POSIX capability for this test only.
    monkeypatch.setattr(
        trust_module,
        "_supports_secure_trust_traversal",
        lambda: True,
    )
    original_open = restricted_verify.os.open
    artifacts = restricted_bundle["artifacts"]
    opens = {
        "plan.json": 0,
        "state.json": 0,
        "commit.txt": 0,
        "version.txt": 0,
    }
    def tracked_open(path, flags, *args, **kwargs):
        candidate = Path(path)
        if (
            candidate == Path(candidate.name)
            and candidate.name in opens
            and kwargs.get("dir_fd") is not None
        ):
            opens[candidate.name] += 1
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(
        restricted_verify.os,
        "open",
        tracked_open,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is True
    assert opens == {
        "plan.json": 1,
        "state.json": 1,
        "commit.txt": 1,
        "version.txt": 1,
    }

def test_symlinked_artifact_ancestor_rejects(
    restricted_bundle,
    tmp_path,
):

    """Do not follow a symlink in the artifact directory ancestry."""
    actual_parent = restricted_bundle["artifacts"].parent
    linked_parent = tmp_path / "linked-project"
    try:
        linked_parent.symlink_to(
            actual_parent,
            target_is_directory=True,
        )
    except (OSError, NotImplementedError):
        pytest.skip(
            "Directory symlinks unavailable on this platform"
        )
    linked_artifacts = linked_parent / "artifacts"
    assert verify_restricted_bundle(
        linked_artifacts,
        restricted_bundle["manifest"],
        restricted_bundle["signature"],
        restricted_bundle["trust_registry"],
        restricted_bundle["key_id"],
        allowed_profiles=frozenset({
            restricted_bundle["profile"]
        }),
    ) is False

def test_restricted_verifier_rejects_symlinked_ancestor(
    restricted_bundle,
    tmp_path,
):
    """Reject a symlink used as the artifact directory itself."""
    artifacts = restricted_bundle["artifacts"]
    linked_artifacts = tmp_path / "linked-artifacts"
    try:
        linked_artifacts.symlink_to(artifacts, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks unavailable on this platform")
    restricted_bundle["artifacts"] = linked_artifacts
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

@pytest.mark.parametrize(
    "name,maximum",
    [
        ("plan.json", 64 * 1024),
        ("state.json", 64 * 1024),
        ("commit.txt", 4 * 1024),
        ("version.txt", 4 * 1024),
    ],
)

def test_oversized_signed_artifact_rejects(
    restricted_bundle,
    name,
    maximum,
):

    """Reject oversized content even when its signed digest matches."""
    content = b"x" * (maximum + 1)
    update_artifact_and_resign(
        restricted_bundle,
        name,
        content,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

@pytest.mark.parametrize(
    "name,maximum",
    [
        ("plan.json", 64 * 1024),
        ("state.json", 64 * 1024),
        ("commit.txt", 4 * 1024),
        ("version.txt", 4 * 1024),
    ],
)

def test_oversized_declared_artifact_rejects(
    restricted_bundle,
    name,
    maximum,
):

    """Reject excessive signed artifact sizes."""
    manifest = json.loads(
        restricted_bundle["manifest"].read_bytes()
    )
    for entry in manifest["artifacts"]:
        if entry["name"] == name:
            entry["size_bytes"] = maximum + 1
    resign(restricted_bundle, manifest)
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

@pytest.mark.parametrize(
    "name,maximum",
    [
        ("plan.json", 64 * 1024),
        ("state.json", 64 * 1024),
        ("commit.txt", 4 * 1024),
        ("version.txt", 4 * 1024),
    ],
)

def test_oversized_declaration_rejected_before_artifact_read(
    restricted_bundle,
    monkeypatch,
    name,
    maximum,
):

    """Reject oversized signed declarations before opening artifacts."""
    import evidence_engine.restricted_verify as restricted_verify
    import evidence_engine.trust as trust_module
    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")
    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")
    monkeypatch.setattr(
        restricted_verify, "_supports_secure_restricted_traversal", lambda: True
    )
    monkeypatch.setattr(
        trust_module, "_supports_secure_trust_traversal", lambda: True
    )
    manifest = json.loads(
        restricted_bundle["manifest"].read_bytes()
    )
    for entry in manifest["artifacts"]:
        if entry["name"] == name:
            entry["size_bytes"] = maximum + 1
    resign(restricted_bundle, manifest)
    original_open = restricted_verify.os.open
    opens = []
    def tracked_open(path, flags, *args, **kwargs):
        if Path(path) == Path(name) and kwargs.get("dir_fd") is not None:
            opens.append(name)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(
        restricted_verify.os,
        "open",
        tracked_open,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False
    assert opens == []

def test_restricted_artifact_rejects_nonregular_open_descriptor(
    restricted_bundle,
    monkeypatch,
    tmp_path,
):

    """Reject a non-regular descriptor despite a valid artifact path."""
    import evidence_engine.restricted_verify as restricted_verify
    # Preserve established POSIX capability while os.open is patched.
    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")
    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: True,
    )
    import evidence_engine.trust as trust_module
    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")
    # The os.open wrapper below is not registered in os.supports_dir_fd.
    # Preserve the established POSIX capability for this test only.
    monkeypatch.setattr(
        trust_module,
        "_supports_secure_trust_traversal",
        lambda: True,
    )
    artifact_path = restricted_bundle["artifacts"] / "plan.json"
    directory_path = tmp_path / "substituted-directory"
    directory_path.mkdir()
    original_open = restricted_verify.os.open
    substituted = []
    def substituted_open(path, flags, *args, **kwargs):
        if Path(path) == Path("plan.json") and kwargs.get("dir_fd") is not None:
            substituted.append(artifact_path)
            return original_open(directory_path, restricted_verify.os.O_RDONLY | restricted_verify.os.O_DIRECTORY)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(
        restricted_verify.os,
        "open",
        substituted_open,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False
    assert substituted == [artifact_path]

@pytest.mark.parametrize(
    "field,maximum",
    [
        ("manifest", 256 * 1024),
        ("signature", 4 * 1024),
    ],
)

def test_oversized_restricted_metadata_rejects(
    restricted_bundle,
    field,
    maximum,
):

    """Reject metadata larger than the configured size limit."""
    path = restricted_bundle[field]
    path.write_bytes(b"x" * (maximum + 1))
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False

@pytest.mark.parametrize(
    "field,maximum",
    [
        ("manifest", 256 * 1024),
        ("signature", 4 * 1024),
    ],
)

def test_oversized_metadata_rejected_before_read(
    restricted_bundle,
    monkeypatch,
    field,
    maximum,
):

    """Reject oversized metadata before reading the target file."""
    import evidence_engine.restricted_verify as restricted_verify
    # Preserve established POSIX capability while os.open is patched.
    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")
    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: True,
    )
    path = restricted_bundle[field]
    path.write_bytes(b"x" * (maximum + 1))
    original_open = restricted_verify.os.open
    original_fdopen = restricted_verify.os.fdopen
    target_descriptors = set()
    target_reads = []
    def tracked_open(candidate, flags, *args, **kwargs):
        descriptor = original_open(
            candidate,
            flags,
            *args,
            **kwargs,
        )
        if (
                Path(candidate).name == path.name
                and kwargs.get("dir_fd") is not None
            ):
            target_descriptors.add(descriptor)
        return descriptor
    class TrackedStream:
        def __init__(self, stream):
            self._stream = stream
        def __enter__(self):
            self._stream.__enter__()
            return self
        def __exit__(self, exc_type, exc_value, traceback):
            return self._stream.__exit__(
                exc_type,
                exc_value,
                traceback,
            )
        def fileno(self):
            return self._stream.fileno()
        def read(self, *args, **kwargs):
            target_reads.append((args, kwargs))
            return self._stream.read(*args, **kwargs)
    def tracked_fdopen(fd, *args, **kwargs):
        stream = original_fdopen(fd, *args, **kwargs)
        if fd in target_descriptors:
            return TrackedStream(stream)
        return stream
    monkeypatch.setattr(
        restricted_verify.os,
        "open",
        tracked_open,
    )
    monkeypatch.setattr(
        restricted_verify.os,
        "fdopen",
        tracked_fdopen,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False
    assert target_descriptors
    assert target_reads == []

def test_restricted_verifier_reads_trusted_key_once(
    restricted_bundle,
    monkeypatch,
):

    import evidence_engine.trust as trust_module
    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")
    original_reader = trust_module._read_secure_project_file
    reads = []
    def counting_reader(project_root, relative_path, *, label, maximum):
        reads.append((Path(relative_path), label, maximum))
        return original_reader(
            project_root,
            relative_path,
            label=label,
            maximum=maximum,
        )
    monkeypatch.setattr(
        trust_module,
        "_read_secure_project_file",
        counting_reader,
    )
    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is True
    registry_reads = [
        entry for entry in reads
        if entry[1] == "Restricted trust registry"
    ]
    key_reads = [
        entry for entry in reads
        if entry[1] == "Restricted public key"
    ]
    assert len(registry_reads) == 1
    assert len(key_reads) == 1
    assert registry_reads[0][2] == 64 * 1024
    assert key_reads[0][2] == 16 * 1024
    assert registry_reads[0][0] == Path("config/trust_registry.json")
    assert key_reads[0][0] == Path("keys/public.pem")

def test_restricted_artifact_parent_swap_does_not_follow_symlink(
    restricted_bundle,
    monkeypatch,
    tmp_path,
):
    """Directory replacement cannot redirect descriptor-relative reads."""
    import os
    import evidence_engine.restricted_verify as restricted_verify
    import evidence_engine.trust as trust_module
    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")
    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")
    artifacts = restricted_bundle["artifacts"]
    original_directory = artifacts.with_name("artifacts-original")
    attacker_directory = tmp_path / "attacker-artifacts"
    attacker_directory.mkdir()
    # An attacker-controlled directory must not be accepted as the source.
    for name in ("plan.json", "state.json", "commit.txt", "version.txt"):
        (attacker_directory / name).write_bytes((artifacts / name).read_bytes())
    (attacker_directory / "plan.json").write_bytes(b"attacker-controlled")
    original_identity = (artifacts.stat().st_dev, artifacts.stat().st_ino)
    original_open = os.open
    swapped = False
    followed_attacker_directory = False
    pinned_directory_verified = False
    # os.open monkeypatches alter os.supports_dir_fd membership checks.
    monkeypatch.setattr(
        restricted_verify, "_supports_secure_restricted_traversal", lambda: True
    )
    monkeypatch.setattr(
        trust_module, "_supports_secure_trust_traversal", lambda: True
    )
    def tracked_open(path, flags, *args, **kwargs):
        nonlocal swapped, followed_attacker_directory, pinned_directory_verified
        candidate = Path(path)
        directory_fd = kwargs.get("dir_fd")
        if candidate == Path("plan.json") and directory_fd is not None:
            if not swapped:
                # This occurs after the artifact directory FD was acquired.
                artifacts.rename(original_directory)
                artifacts.symlink_to(attacker_directory, target_is_directory=True)
                swapped = True
            opened_directory = os.fstat(directory_fd)
            pinned_directory_verified = (
                opened_directory.st_dev, opened_directory.st_ino
            ) == original_identity
        if swapped and candidate == artifacts / "plan.json" and directory_fd is None:
            followed_attacker_directory = True
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(restricted_verify.os, "open", tracked_open)
    try:
        verified = verify(
            restricted_bundle,
            frozenset({restricted_bundle["profile"]}),
        )
    finally:
        if artifacts.is_symlink():
            artifacts.unlink()
        if original_directory.exists():
            original_directory.rename(artifacts)
    assert swapped, "Race injection did not execute"
    assert pinned_directory_verified, "Artifact open used a different directory"
    assert not followed_attacker_directory, "Artifact open followed swapped pathname"
    assert verified is True, "Pinned original bundle should still verify"


@pytest.mark.parametrize("field", ["manifest", "signature"])
def test_restricted_metadata_fifo_rejects_without_blocking(
    restricted_bundle,
    field,
):
    """Reject a metadata FIFO without waiting for a writer."""
    import os
    import subprocess
    import sys

    if os.name != "posix" or not hasattr(os, "mkfifo"):
        pytest.skip("POSIX FIFOs required")

    path = restricted_bundle[field]
    path.unlink()
    os.mkfifo(path)

    script = """
import sys
from pathlib import Path
from evidence_engine.restricted_verify import verify_restricted_bundle

root = Path(sys.argv[1])
result = verify_restricted_bundle(
    root / "artifacts",
    root / "bundle" / "manifest.json",
    root / "bundle" / "manifest.sig",
    root / "config" / "trust_registry.json",
    sys.argv[2],
    allowed_profiles=frozenset({sys.argv[3]}),
)
sys.exit(0 if result is False else 1)
"""

    project = restricted_bundle["artifacts"].parent

    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(project),
                restricted_bundle["key_id"],
                restricted_bundle["profile"],
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"Restricted verifier blocked opening FIFO metadata: {field}"
        )

    assert completed.returncode == 0, completed.stderr



@pytest.mark.parametrize("field", ["manifest", "signature"])
def test_restricted_metadata_parent_swap_uses_pinned_directory(
    restricted_bundle,
    monkeypatch,
    tmp_path,
    field,
):
    """A metadata parent swap must not redirect descriptor-relative reads."""
    import os

    import evidence_engine.restricted_verify as restricted_verify

    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")

    metadata_path = restricted_bundle[field]
    metadata_directory = metadata_path.parent
    original_directory = metadata_directory.with_name(
        metadata_directory.name + "-original"
    )

    attacker_directory = tmp_path / "attacker-metadata"
    attacker_directory.mkdir()

    # Both files are present, but attacker-controlled and invalid.
    (attacker_directory / "manifest.json").write_bytes(
        b"attacker-controlled-manifest"
    )
    (attacker_directory / "manifest.sig").write_bytes(
        b"attacker-controlled-signature"
    )

    original_identity = (
        metadata_directory.stat().st_dev,
        metadata_directory.stat().st_ino,
    )
    expected_content = metadata_path.read_bytes()

    original_open = os.open
    swapped = False
    pinned_directory_verified = False
    followed_attacker_directory = False

    # Monkeypatching os.open changes membership checks in
    # os.supports_dir_fd, so preserve the previously verified capability.
    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: True,
    )

    def tracked_open(path, flags, *args, **kwargs):
        nonlocal swapped
        nonlocal pinned_directory_verified
        nonlocal followed_attacker_directory

        candidate = Path(path)
        directory_fd = kwargs.get("dir_fd")

        if candidate == Path(metadata_path.name) and directory_fd is not None:
            if not swapped:
                metadata_directory.rename(original_directory)
                metadata_directory.symlink_to(
                    attacker_directory,
                    target_is_directory=True,
                )
                swapped = True

            opened_directory = os.fstat(directory_fd)
            pinned_directory_verified = (
                opened_directory.st_dev,
                opened_directory.st_ino,
            ) == original_identity

        if (
            swapped
            and candidate == metadata_path
            and directory_fd is None
        ):
            followed_attacker_directory = True

        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(restricted_verify.os, "open", tracked_open)

    try:
        actual_content = restricted_verify._read_restricted_metadata(
            metadata_path,
            field,
            restricted_verify._RESTRICTED_METADATA_LIMITS[field],
        )
    finally:
        if metadata_directory.is_symlink():
            metadata_directory.unlink()

        if original_directory.exists():
            original_directory.rename(metadata_directory)

    assert swapped, "Metadata race injection did not execute"
    assert pinned_directory_verified, (
        "Metadata open did not use the original pinned directory"
    )
    assert not followed_attacker_directory, (
        "Metadata open followed the swapped pathname"
    )
    assert actual_content == expected_content, (
        "Metadata content changed after parent-directory replacement"
    )


@pytest.mark.parametrize("field", ["manifest", "signature"])
@pytest.mark.parametrize("failure", [False, True])
def test_restricted_metadata_closes_descriptors(
    restricted_bundle,
    monkeypatch,
    field,
    failure,
):
    """Metadata reads close their file and parent descriptors."""
    import os

    import evidence_engine.restricted_verify as restricted_verify

    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")

    path = restricted_bundle[field]
    expected = path.read_bytes()

    original_open = os.open
    original_fdopen = os.fdopen
    opened_descriptors = []

    # Patching os.open changes os.supports_dir_fd membership checks.
    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: True,
    )

    def tracked_open(path_arg, flags, *args, **kwargs):
        descriptor = original_open(
            path_arg,
            flags,
            *args,
            **kwargs,
        )
        opened_descriptors.append(descriptor)
        return descriptor

    def tracked_fdopen(descriptor, *args, **kwargs):
        if failure:
            raise OSError("injected fdopen failure")

        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(restricted_verify.os, "open", tracked_open)

    if failure:
        monkeypatch.setattr(
            restricted_verify.os,
            "fdopen",
            tracked_fdopen,
        )

    try:
        if failure:
            with pytest.raises(
                OSError,
                match="injected fdopen failure",
            ):
                restricted_verify._read_restricted_metadata(
                    path,
                    field,
                    restricted_verify._RESTRICTED_METADATA_LIMITS[field],
                )
        else:
            content = restricted_verify._read_restricted_metadata(
                path,
                field,
                restricted_verify._RESTRICTED_METADATA_LIMITS[field],
            )
            assert content == expected

        assert opened_descriptors

        for descriptor in opened_descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        monkeypatch.undo()


def test_restricted_verifier_fails_closed_without_secure_traversal(
    restricted_bundle,
    monkeypatch,
):
    """Restricted verification rejects unavailable secure traversal."""
    import evidence_engine.restricted_verify as restricted_verify

    monkeypatch.setattr(
        restricted_verify,
        "_supports_secure_restricted_traversal",
        lambda: False,
    )

    assert verify(
        restricted_bundle,
        frozenset({restricted_bundle["profile"]}),
    ) is False


def test_restricted_artifact_replacement_after_read_uses_original_bytes(
    restricted_bundle,
    monkeypatch,
):
    """Replacing an artifact after its read cannot change validated bytes."""
    import os

    import evidence_engine.restricted_verify as restricted_verify

    if not restricted_verify._supports_secure_restricted_traversal():
        pytest.skip("Secure restricted traversal unavailable")

    import evidence_engine.trust as trust_module

    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")

    artifacts = restricted_bundle["artifacts"]
    plan_path = artifacts / "plan.json"

    original_bytes = plan_path.read_bytes()
    replacement_bytes = b"attacker-controlled-plan"

    original_reader = restricted_verify._read_restricted_artifact

    replaced = False

    def replacing_reader(directory_fd, name, expected_size):
        nonlocal replaced

        content = original_reader(
            directory_fd,
            name,
            expected_size,
        )

        if name == "plan.json" and not replaced:
            replacement_path = artifacts / "plan-replacement.tmp"

            replacement_path.write_bytes(replacement_bytes)
            os.replace(replacement_path, plan_path)

            replaced = True

        return content

    monkeypatch.setattr(
        restricted_verify,
        "_read_restricted_artifact",
        replacing_reader,
    )

    try:
        result = verify(
            restricted_bundle,
            frozenset({restricted_bundle["profile"]}),
        )
    finally:
        plan_path.write_bytes(original_bytes)

    assert replaced, "Artifact replacement was not injected"
    assert result is True, (
        "Verifier should validate the original signed artifact bytes"
    )
