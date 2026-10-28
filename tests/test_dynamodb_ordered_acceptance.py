import pytest

from evidence_engine.aws.acceptance import DynamoDBAcceptanceState


DIGEST = "a" * 64


class FakeDynamoDBError(Exception):
    def __init__(self, code, reasons=None):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        if reasons is not None:
            self.response["CancellationReasons"] = reasons


class FakeDynamoDBClient:
    def __init__(self):
        self.calls = []
        self.error = None

    def put_item(self, **kwargs):
        return {}

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {}


def make_state(client):
    return DynamoDBAcceptanceState(client, "acceptance-state")


def ordered_args():
    return {
        "consumer_id": "consumer-a",
        "stream_id": "terraform-production",
        "run_number": 42,
        "run_attempt": 1,
    }


def test_ordered_acceptance_uses_atomic_transaction():
    client = FakeDynamoDBClient()
    state = make_state(client)

    result = state.accept_ordered(DIGEST, **ordered_args())

    assert result == "accepted"
    assert len(client.calls) == 1

    items = client.calls[0]["TransactItems"]
    assert len(items) == 2

    digest_put = items[0]["Put"]
    checkpoint_put = items[1]["Put"]

    assert digest_put["Item"]["sk"] == {"S": f"DIGEST#{DIGEST}"}
    assert "attribute_not_exists" in digest_put["ConditionExpression"]
    assert checkpoint_put["Item"]["sk"] == {
        "S": "CHECKPOINT#terraform-production"
    }
    assert "#rn < :rn" in checkpoint_put["ConditionExpression"]
    assert "#ra < :ra" in checkpoint_put["ConditionExpression"]


def test_ordered_acceptance_reports_replay():
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError(
        "TransactionCanceledException",
        [
            {"Code": "ConditionalCheckFailed"},
            {"Code": "None"},
        ],
    )

    result = make_state(client).accept_ordered(DIGEST, **ordered_args())

    assert result == "replay"


def test_ordered_acceptance_reports_stale_checkpoint():
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError(
        "TransactionCanceledException",
        [
            {"Code": "None"},
            {"Code": "ConditionalCheckFailed"},
        ],
    )

    result = make_state(client).accept_ordered(DIGEST, **ordered_args())

    assert result == "stale"


def test_ordered_acceptance_propagates_unexpected_errors():
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError("AccessDeniedException")

    with pytest.raises(FakeDynamoDBError):
        make_state(client).accept_ordered(DIGEST, **ordered_args())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("consumer_id", ""),
        ("stream_id", "../invalid"),
        ("run_number", 0),
        ("run_attempt", True),
    ],
)
def test_ordered_acceptance_validates_input(field, value):
    client = FakeDynamoDBClient()
    args = ordered_args()
    args[field] = value

    with pytest.raises(ValueError):
        make_state(client).accept_ordered(DIGEST, **args)

    assert client.calls == []
