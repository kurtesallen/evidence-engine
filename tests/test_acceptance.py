
from concurrent.futures import ThreadPoolExecutor

import pytest

from evidence_engine.acceptance import InMemoryAcceptanceState


def test_first_acceptance_succeeds_and_duplicate_is_rejected():
    state = InMemoryAcceptanceState()
    digest = "a" * 64

    assert state.accept_once(digest) is True
    assert state.accept_once(digest) is False


def test_distinct_bundles_can_be_accepted():
    state = InMemoryAcceptanceState()

    assert state.accept_once("a" * 64) is True
    assert state.accept_once("b" * 64) is True


@pytest.mark.parametrize("digest", ["", "not-a-digest", "A" * 64, None])
def test_invalid_digest_is_rejected(digest):
    state = InMemoryAcceptanceState()

    with pytest.raises(ValueError, match="Invalid bundle digest"):
        state.accept_once(digest)


def test_concurrent_duplicate_acceptance_succeeds_only_once():
    state = InMemoryAcceptanceState()
    digest = "c" * 64

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(state.accept_once, [digest] * 100))

    assert results.count(True) == 1
    assert results.count(False) == 99


def test_ordered_acceptance_rejects_replay_and_stale_positions():
    state = InMemoryAcceptanceState()
    common = {
        "consumer_id": "consumer-a",
        "stream_id": "terraform-production",
    }

    assert state.accept_ordered(
        "a" * 64, **common, run_number=42, run_attempt=1
    ) == "accepted"

    assert state.accept_ordered(
        "a" * 64, **common, run_number=42, run_attempt=1
    ) == "replay"

    assert state.accept_ordered(
        "b" * 64, **common, run_number=41, run_attempt=9
    ) == "stale"

    assert state.accept_ordered(
        "c" * 64, **common, run_number=42, run_attempt=1
    ) == "stale"

    assert state.accept_ordered(
        "d" * 64, **common, run_number=42, run_attempt=2
    ) == "accepted"


def test_ordered_acceptance_scopes_checkpoints():
    state = InMemoryAcceptanceState()

    assert state.accept_ordered(
        "a" * 64,
        consumer_id="consumer-a",
        stream_id="terraform-production",
        run_number=42,
        run_attempt=1,
    ) == "accepted"

    # A separate logical consumer has its own checkpoint.
    assert state.accept_ordered(
        "b" * 64,
        consumer_id="consumer-b",
        stream_id="terraform-production",
        run_number=1,
        run_attempt=1,
    ) == "accepted"

    # A separate stream also has its own checkpoint.
    assert state.accept_ordered(
        "c" * 64,
        consumer_id="consumer-a",
        stream_id="terraform-staging",
        run_number=1,
        run_attempt=1,
    ) == "accepted"
