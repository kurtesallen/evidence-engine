from pathlib import Path

import os
import pytest


from evidence_engine.agents.collection import CollectionAgent
from evidence_engine.agents.base import AgentResult
from evidence_engine.policy import PolicyEngine


def test_collection_agent_rejects_non_directory(tmp_path: Path):
    root = tmp_path / "missing"
    agent = CollectionAgent(root=root)

    result = agent.run()

    assert isinstance(result, AgentResult)
    assert result.success is False
    assert result.error == "artifacts-root-not-directory"


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink privilege not available")
def test_collection_agent_rejects_symlinks(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    target = root / "real.txt"
    target.write_text("data", encoding="utf-8")
    symlink = root / "link.txt"
    symlink.symlink_to(target)

    agent = CollectionAgent(root=root)
    result = agent.run()

    assert result.success is False
    assert "symlink-rejected" in result.error


def test_collection_agent_rejects_directories(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "subdir").mkdir()

    agent = CollectionAgent(root=root)
    result = agent.run()

    assert result.success is False
    assert "non-file-entry-rejected" in result.error


def test_collection_agent_collects_files_and_applies_policy(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "b.json").write_text("b", encoding="utf-8")

    agent = CollectionAgent(root=root, policy=PolicyEngine())
    result = agent.run()

    assert result.success is True
    assert result.error is None
    names = [p.name for p in result.data["files"]]
    assert names == ["a.txt", "b.json"]
    assert "files" in result.data["metadata"]
    assert result.audit["policy_reason"] == "collection-allowed"


def test_collection_agent_fail_closed_on_policy_denial(tmp_path: Path):
    class DenyPolicy(PolicyEngine):
        def evaluate_collection(self, metadata):
            from evidence_engine.policy import PolicyDecision
            return PolicyDecision(
                allowed=False,
                reason="collection-denied",
                details={"cause": "test"},
            )

    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")

    agent = CollectionAgent(root=root, policy=DenyPolicy())
    result = agent.run()

    assert result.success is False
    assert result.error == "collection-denied"
    assert result.audit["policy_version"] == agent._policy.version
