
from __future__ import annotations

from typing import Any

import pytest

from evidence_engine.aws.acceptance import DynamoDBAcceptanceState


VALID_DIGEST = "a" * 64


class FakeDynamoDBError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeDynamoDBClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.error: Exception | None = None

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)

        if self.error is not None:
            raise self.error

        return {}


def test_first_acceptance_writes_digest_conditionally() -> None:
    client = FakeDynamoDBClient()
    state = DynamoDBAcceptanceState(client, "acceptance-state")

    assert state.accept_once(VALID_DIGEST) is True
    assert len(client.calls) == 1

    call = client.calls[0]

    assert call["TableName"] == "acceptance-state"
    assert call["Item"] == {
        "pk": {"S": "LEGACY_GLOBAL"},
        "sk": {"S": f"DIGEST#{VALID_DIGEST}"},
        "bundle_digest": {"S": VALID_DIGEST},
    }
    assert call["ConditionExpression"] == (
        "attribute_not_exists(pk) AND attribute_not_exists(sk)"
    )


def test_existing_digest_returns_false() -> None:
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError("ConditionalCheckFailedException")

    state = DynamoDBAcceptanceState(client, "acceptance-state")

    assert state.accept_once(VALID_DIGEST) is False
    assert len(client.calls) == 1


def test_unexpected_storage_error_propagates() -> None:
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError("AccessDeniedException")

    state = DynamoDBAcceptanceState(client, "acceptance-state")

    with pytest.raises(FakeDynamoDBError):
        state.accept_once(VALID_DIGEST)


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "not-a-digest",
        "A" * 64,
        "a" * 63,
        "a" * 65,
        None,
    ],
)
def test_invalid_digest_is_rejected_before_write(digest: Any) -> None:
    client = FakeDynamoDBClient()
    state = DynamoDBAcceptanceState(client, "acceptance-state")

    with pytest.raises(ValueError, match="Invalid bundle digest"):
        state.accept_once(digest)

    assert client.calls == []


def test_empty_table_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="table_name"):
        DynamoDBAcceptanceState(FakeDynamoDBClient(), " ")
