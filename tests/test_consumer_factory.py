"""Tests for configured consumer construction."""

import pytest

from evidence_engine.acceptance import InMemoryAcceptanceState
from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.agents.consumer_factory import create_consumer
from evidence_engine.aws.acceptance import DynamoDBAcceptanceState
from evidence_engine.aws.config import BACKEND_ENV, TABLE_ENV


class FakeDynamoDBClient:
    def put_item(self, **kwargs):
        return {}


def test_consumer_factory_requires_explicit_backend(tmp_path):
    with pytest.raises(ValueError, match=BACKEND_ENV):
        create_consumer(tmp_path, environ={})


def test_consumer_factory_constructs_memory_consumer(tmp_path):
    consumer = create_consumer(
        tmp_path,
        expected_source="local-claimed",
        expected_key_id="test-key",
        environ={BACKEND_ENV: "memory"},
    )

    assert isinstance(consumer, ConsumerAgent)
    assert isinstance(consumer._acceptance_state, InMemoryAcceptanceState)
    assert consumer._expected_source == "local-claimed"
    assert consumer._expected_key_id == "test-key"


def test_consumer_factory_constructs_dynamodb_consumer(tmp_path):
    fake_client = FakeDynamoDBClient()

    consumer = create_consumer(
        tmp_path,
        expected_key_id="test-key",
        environ={
            BACKEND_ENV: "dynamodb",
            TABLE_ENV: "acceptance-test",
        },
        client=fake_client,
    )

    assert isinstance(consumer._acceptance_state, DynamoDBAcceptanceState)
    assert consumer._acceptance_state._client is fake_client


def test_consumer_factory_does_not_fallback_on_bad_dynamodb_config(tmp_path):
    with pytest.raises(ValueError, match=TABLE_ENV):
        create_consumer(
            tmp_path,
            environ={BACKEND_ENV: "dynamodb"},
        )


def test_consumer_factory_propagates_client_initialization_errors(tmp_path):
    def broken_client_factory(*args, **kwargs):
        raise RuntimeError("simulated client initialization failure")

    with pytest.raises(RuntimeError, match="initialization failure"):
        create_consumer(
            tmp_path,
            environ={
                BACKEND_ENV: "dynamodb",
                TABLE_ENV: "acceptance-test",
            },
            client_factory=broken_client_factory,
        )
