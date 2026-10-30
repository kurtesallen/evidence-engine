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
        self.errors = []

    def put_item(self, **kwargs):
        return {}

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)

        if self.errors:
            raise self.errors.pop(0)

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

def test_ordered_acceptance_retries_transient_transaction_conflicts(monkeypatch):
    client = FakeDynamoDBClient()
    conflict = FakeDynamoDBError(
        "TransactionCanceledException",
        [
            {"Code": "TransactionConflict"},
            {"Code": "None"},
        ],
    )
    client.errors = [conflict, conflict]

    sleeps = []
    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.sleep",
        lambda delay: sleeps.append(delay),
    )

    result = make_state(client).accept_ordered(DIGEST, **ordered_args())

    assert result == "accepted"
    assert len(client.calls) == 3
    assert len(sleeps) == 2
    assert all(delay >= 0 for delay in sleeps)


def test_ordered_acceptance_reuses_client_request_token_across_retries(
    monkeypatch,
):
    client = FakeDynamoDBClient()
    client.errors = [
        FakeDynamoDBError(
            "TransactionConflictException",
        ),
    ]

    sleeps = []
    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.sleep",
        lambda delay: sleeps.append(delay),
    )

    state = DynamoDBAcceptanceState(client, "acceptance")

    result = state.accept_ordered(
        "a" * 64,
        consumer_id="consumer-a",
        stream_id="stream-a",
        run_number=10,
        run_attempt=1,
    )

    assert result == "accepted"
    assert len(client.calls) == 2

    first_token = client.calls[0]["ClientRequestToken"]
    second_token = client.calls[1]["ClientRequestToken"]

    assert first_token == second_token
    assert len(first_token) == 32
    assert len(sleeps) == 1



def test_ordered_acceptance_retries_transaction_in_progress(
    monkeypatch,
):
    client = FakeDynamoDBClient()
    client.errors = [
        FakeDynamoDBError("TransactionInProgressException"),
    ]

    now = [100.0]
    sleeps = []
    call_times = []

    def fake_monotonic():
        return now[0]

    def fake_sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    original_transact = client.transact_write_items

    def timed_transact(**kwargs):
        call_times.append(now[0])
        return original_transact(**kwargs)

    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.monotonic",
        fake_monotonic,
    )
    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.sleep",
        fake_sleep,
    )
    monkeypatch.setattr(
        client,
        "transact_write_items",
        timed_transact,
    )

    state = DynamoDBAcceptanceState(client, "acceptance")

    result = state.accept_ordered(
        "b" * 64,
        consumer_id="consumer-a",
        stream_id="stream-a",
        run_number=10,
        run_attempt=1,
    )

    assert result == "accepted"
    assert len(client.calls) == 2
    assert len(call_times) == 2
    assert call_times[1] - call_times[0] >= 5.0
    assert sleeps == [5.0]

    assert (
        client.calls[0]["ClientRequestToken"]
        == client.calls[1]["ClientRequestToken"]
    )


def test_ordered_acceptance_stops_after_maximum_retries(
    monkeypatch,
):
    from evidence_engine.aws.acceptance import (
        _MAX_TRANSACTION_ATTEMPTS,
    )

    client = FakeDynamoDBClient()
    client.errors = [
        FakeDynamoDBError("TransactionConflictException")
        for _ in range(_MAX_TRANSACTION_ATTEMPTS)
    ]

    sleeps = []
    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.sleep",
        lambda delay: sleeps.append(delay),
    )

    state = DynamoDBAcceptanceState(client, "acceptance")

    with pytest.raises(FakeDynamoDBError):
        state.accept_ordered(
            "c" * 64,
            consumer_id="consumer-a",
            stream_id="stream-a",
            run_number=10,
            run_attempt=1,
        )

    assert len(client.calls) == _MAX_TRANSACTION_ATTEMPTS
    assert len(sleeps) == _MAX_TRANSACTION_ATTEMPTS - 1


@pytest.mark.parametrize(
    ("reasons", "expected"),
    [
        (
            [
                {"Code": "ConditionalCheckFailed"},
                {"Code": "None"},
            ],
            "replay",
        ),
        (
            [
                {"Code": "None"},
                {"Code": "ConditionalCheckFailed"},
            ],
            "stale",
        ),
    ],
)
def test_ordered_acceptance_does_not_retry_conditional_failures(
    monkeypatch,
    reasons,
    expected,
):
    client = FakeDynamoDBClient()
    client.error = FakeDynamoDBError(
        "TransactionCanceledException",
        reasons,
    )

    def unexpected_sleep(_delay):
        pytest.fail("Conditional failures must not be retried")

    monkeypatch.setattr(
        "evidence_engine.aws.acceptance.time.sleep",
        unexpected_sleep,
    )

    result = make_state(client).accept_ordered(DIGEST, **ordered_args())

    assert result == expected
    assert len(client.calls) == 1
