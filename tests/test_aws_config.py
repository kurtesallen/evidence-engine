"""Tests for explicit acceptance-state backend configuration."""

import pytest

from evidence_engine.acceptance import InMemoryAcceptanceState
from evidence_engine.aws.acceptance import DynamoDBAcceptanceState
from evidence_engine.aws.config import (
    BACKEND_ENV,
    TABLE_ENV,
    create_acceptance_state,
)


class FakeDynamoDBClient:
    def put_item(self, **kwargs):
        return {}


def test_backend_must_be_explicit():
    with pytest.raises(ValueError, match=BACKEND_ENV):
        create_acceptance_state(environ={})


def test_unknown_backend_is_rejected():
    with pytest.raises(ValueError, match=BACKEND_ENV):
        create_acceptance_state(
            environ={BACKEND_ENV: "automatic"}
        )


def test_memory_backend_is_explicit_and_local():
    state = create_acceptance_state(
        environ={BACKEND_ENV: "memory"}
    )

    assert isinstance(state, InMemoryAcceptanceState)


def test_memory_backend_rejects_aws_client_arguments():
    with pytest.raises(ValueError, match="memory backend"):
        create_acceptance_state(
            environ={BACKEND_ENV: "memory"},
            client=FakeDynamoDBClient(),
        )


def test_dynamodb_requires_table_name():
    with pytest.raises(ValueError, match=TABLE_ENV):
        create_acceptance_state(
            environ={BACKEND_ENV: "dynamodb"}
        )


def test_dynamodb_uses_injected_client():
    fake_client = FakeDynamoDBClient()

    state = create_acceptance_state(
        environ={
            BACKEND_ENV: "dynamodb",
            TABLE_ENV: "evidence-acceptance",
        },
        client=fake_client,
    )

    assert isinstance(state, DynamoDBAcceptanceState)
    assert state._client is fake_client
    assert state._table_name == "evidence-acceptance"


def test_dynamodb_client_factory_receives_configured_region():
    calls = []
    fake_client = FakeDynamoDBClient()

    def client_factory(service_name, **kwargs):
        calls.append((service_name, kwargs))
        return fake_client

    state = create_acceptance_state(
        environ={
            BACKEND_ENV: "dynamodb",
            TABLE_ENV: "evidence-acceptance",
            "AWS_REGION": "us-east-1",
        },
        client_factory=client_factory,
    )

    assert isinstance(state, DynamoDBAcceptanceState)
    assert calls == [
        ("dynamodb", {"region_name": "us-east-1"})
    ]


def test_dynamodb_uses_sdk_region_resolution_when_unset():
    calls = []
    fake_client = FakeDynamoDBClient()

    def client_factory(service_name, **kwargs):
        calls.append((service_name, kwargs))
        return fake_client

    create_acceptance_state(
        environ={
            BACKEND_ENV: "dynamodb",
            TABLE_ENV: "evidence-acceptance",
        },
        client_factory=client_factory,
    )

    assert calls == [("dynamodb", {})]


def test_invalid_table_configuration_does_not_create_client():
    calls = []

    def client_factory(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeDynamoDBClient()

    with pytest.raises(ValueError, match=TABLE_ENV):
        create_acceptance_state(
            environ={
                BACKEND_ENV: "dynamodb",
                TABLE_ENV: "   ",
            },
            client_factory=client_factory,
        )

    assert calls == []


def test_client_and_factory_cannot_both_be_supplied():
    with pytest.raises(ValueError, match="not both"):
        create_acceptance_state(
            environ={
                BACKEND_ENV: "dynamodb",
                TABLE_ENV: "evidence-acceptance",
            },
            client=FakeDynamoDBClient(),
            client_factory=lambda *args, **kwargs: FakeDynamoDBClient(),
        )
