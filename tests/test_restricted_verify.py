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
        if candidate.parent == artifacts and candidate.name in opens:
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
    monkeypatch,
):
    """Reject an artifact path whose ancestry fails symlink validation."""
    import evidence_engine.restricted_verify as restricted_verify
    def reject_artifact_ancestry(path, label):
        if path == restricted_bundle["artifacts"]:
            raise ValueError(
                "Restricted artifacts contains a symlink"
            )
    monkeypatch.setattr(
        restricted_verify,
        "_reject_symlink_components",
        reject_artifact_ancestry,
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
    manifest = json.loads(
        restricted_bundle["manifest"].read_bytes()
    )
    for entry in manifest["artifacts"]:
        if entry["name"] == name:
            entry["size_bytes"] = maximum + 1
    resign(restricted_bundle, manifest)
    artifact_path = restricted_bundle["artifacts"] / name
    original_open = restricted_verify.os.open
    opens = []
    def tracked_open(path, flags, *args, **kwargs):
        if Path(path) == artifact_path:
            opens.append(Path(path))
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
        if Path(path) == artifact_path:
            substituted.append(Path(path))
            return original_open(
                directory_path,
                flags,
                *args,
                **kwargs,
            )
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
        if Path(candidate) == path:
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
