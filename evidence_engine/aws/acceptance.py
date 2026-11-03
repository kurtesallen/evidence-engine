"""DynamoDB-backed acceptance state for shared replay detection."""

from __future__ import annotations

import random
import re
import time
import uuid
from typing import Any, Literal


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

AcceptanceOutcome = Literal["accepted", "replay", "stale"]

_MAX_TRANSACTION_ATTEMPTS = 6
_TRANSACTION_BACKOFF_BASE_SECONDS = 0.025
_TRANSACTION_BACKOFF_MAX_SECONDS = 0.5
_TRANSACTION_IN_PROGRESS_RECOVERY_SECONDS = 5.0


def _is_ambiguous_transport_error(exc: Exception) -> bool:
    """Return whether a transport failure may have hidden a committed write.

    Import botocore lazily so this optional adapter remains importable in
    environments that do not install boto3/botocore.
    """
    try:
        from botocore.exceptions import (
            ConnectionClosedError,
            ConnectTimeoutError,
            EndpointConnectionError,
            HTTPClientError,
            ReadTimeoutError,
        )
    except ImportError:
        return False

    return isinstance(
        exc,
        (
            ConnectionClosedError,
            ConnectTimeoutError,
            EndpointConnectionError,
            HTTPClientError,
            ReadTimeoutError,
        ),
    )


class DynamoDBAcceptanceState:
    """Atomically record bundle acceptance in a DynamoDB table.

    The supplied DynamoDB client must be a boto3 low-level client.
    The table must have a string partition key named ``pk`` and a
    string sort key named ``sk``.
    """

    def __init__(self, client: Any, table_name: str) -> None:
        if not isinstance(table_name, str) or not table_name.strip():
            raise ValueError("table_name must be a non-empty string")

        if not callable(getattr(client, "put_item", None)):
            raise TypeError("client must provide put_item")

        self._client = client
        self._table_name = table_name

    def accept_once(self, bundle_digest: str) -> bool:
        """Return True if recorded for the first time, False if it exists.

        Unexpected DynamoDB errors propagate to the caller, which must fail
        closed rather than treating an unavailable store as acceptance.
        """
        if not isinstance(bundle_digest, str) or not _DIGEST_RE.fullmatch(
            bundle_digest
        ):
            raise ValueError("Invalid bundle digest")

        try:
            self._client.put_item(
                TableName=self._table_name,
                Item={
                    "pk": {"S": "LEGACY_GLOBAL"},
                    "sk": {"S": f"DIGEST#{bundle_digest}"},
                    "bundle_digest": {"S": bundle_digest},
                },
                ConditionExpression=(
                    "attribute_not_exists(pk) AND attribute_not_exists(sk)"
                ),
            )
        except Exception as exc:
            # Avoid requiring botocore just to import this optional adapter.
            # Only the specific conditional-write conflict means "already seen".
            response = getattr(exc, "response", None)
            error = response.get("Error", {}) if isinstance(response, dict) else {}

            if (
                isinstance(error, dict)
                and error.get("Code") == "ConditionalCheckFailedException"
            ):
                return False

            raise

        return True

    def _digest_was_committed(
        self,
        bundle_digest: str,
        *,
        consumer_id: str,
        stream_id: str,
        request_token: str,
    ) -> bool:
        """Confirm that this specific ambiguous transaction committed.

        A strongly consistent read can confirm the write only when the
        persisted request token matches the transaction being recovered.

        An absent record, mismatched token, or failed read is inconclusive.
        """
        get_item = getattr(self._client, "get_item", None)
        if not callable(get_item):
            return False

        try:
            response = get_item(
                TableName=self._table_name,
                Key={
                    "pk": {"S": f"CONSUMER#{consumer_id}"},
                    "sk": {"S": f"DIGEST#{bundle_digest}"},
                },
                ConsistentRead=True,
            )
        except Exception:
            # The caller preserves and re-raises the original transport error.
            return False

        if not isinstance(response, dict):
            return False

        item = response.get("Item")
        if not isinstance(item, dict):
            return False

        return (
            item.get("record_type") == {"S": "DIGEST"}
            and item.get("bundle_digest") == {"S": bundle_digest}
            and item.get("stream_id") == {"S": stream_id}
            and item.get("acceptance_request_token") == {"S": request_token}
        )

    def accept_ordered(
        self,
        bundle_digest: str,
        *,
        consumer_id: str,
        stream_id: str,
        run_number: int,
        run_attempt: int,
    ) -> AcceptanceOutcome:
        """Atomically record a digest and advance its stream checkpoint."""
        if not isinstance(bundle_digest, str) or not _DIGEST_RE.fullmatch(
            bundle_digest
        ):
            raise ValueError("Invalid bundle digest")

        if not isinstance(consumer_id, str) or not _IDENTIFIER_RE.fullmatch(
            consumer_id
        ):
            raise ValueError("Invalid consumer ID")

        if not isinstance(stream_id, str) or not _IDENTIFIER_RE.fullmatch(
            stream_id
        ):
            raise ValueError("Invalid stream ID")

        for name, value in (
            ("run_number", run_number),
            ("run_attempt", run_attempt),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"Invalid {name}")

        transact = getattr(self._client, "transact_write_items", None)
        if not callable(transact):
            raise TypeError("client must provide transact_write_items")

        client_request_token = uuid.uuid4().hex

        digest_item = {
            "pk": {"S": f"CONSUMER#{consumer_id}"},
            "sk": {"S": f"DIGEST#{bundle_digest}"},
            "record_type": {"S": "DIGEST"},
            "bundle_digest": {"S": bundle_digest},
            "stream_id": {"S": stream_id},
            "acceptance_request_token": {"S": client_request_token},
        }

        checkpoint_item = {
            "pk": {"S": f"CONSUMER#{consumer_id}"},
            "sk": {"S": f"CHECKPOINT#{stream_id}"},
            "record_type": {"S": "CHECKPOINT"},
            "stream_id": {"S": stream_id},
            "run_number": {"N": str(run_number)},
            "run_attempt": {"N": str(run_attempt)},
            "bundle_digest": {"S": bundle_digest},
        }

        request = {
            "TransactItems": [
                {
                    "Put": {
                        "TableName": self._table_name,
                        "Item": digest_item,
                        "ConditionExpression": (
                            "attribute_not_exists(pk) AND attribute_not_exists(sk)"
                        ),
                    }
                },
                {
                    "Put": {
                        "TableName": self._table_name,
                        "Item": checkpoint_item,
                        "ConditionExpression": (
                            "attribute_not_exists(pk) OR #rn < :rn "
                            "OR (#rn = :rn AND #ra < :ra)"
                        ),
                        "ExpressionAttributeNames": {
                            "#rn": "run_number",
                            "#ra": "run_attempt",
                        },
                        "ExpressionAttributeValues": {
                            ":rn": {"N": str(run_number)},
                            ":ra": {"N": str(run_attempt)},
                        },
                    }
                },
            ],
            # Keep this token and the transaction payload unchanged across
            # retries so DynamoDB can recognize identical transaction attempts.
            "ClientRequestToken": client_request_token,
        }

        # Measure the recovery interval from the first transaction attempt.
        first_attempt_at = time.monotonic()

        for attempt in range(_MAX_TRANSACTION_ATTEMPTS):
            try:
                transact(**request)
                return "accepted"

            except Exception as exc:
                response = getattr(exc, "response", None)
                error = (
                    response.get("Error", {})
                    if isinstance(response, dict)
                    else {}
                )
                code = error.get("Code") if isinstance(error, dict) else None

                if _is_ambiguous_transport_error(exc):
                    if self._digest_was_committed(
                        bundle_digest,
                        consumer_id=consumer_id,
                        stream_id=stream_id,
                        request_token=client_request_token,
                    ):
                        return "accepted"

                    # An absent record, mismatched token, or failed read is
                    # inconclusive. Preserve the original transport exception.
                    raise

                transaction_in_progress = (
                    code == "TransactionInProgressException"
                )

                retryable = transaction_in_progress or (
                    code == "TransactionConflictException"
                )

                if code == "TransactionCanceledException":
                    reasons = response.get("CancellationReasons", [])

                    if not isinstance(reasons, list) or len(reasons) != 2:
                        raise

                    codes = [
                        item.get("Code") if isinstance(item, dict) else None
                        for item in reasons
                    ]

                    if "TransactionConflict" in codes:
                        retryable = True
                    elif codes[0] == "ConditionalCheckFailed":
                        return "replay"
                    elif codes[1] == "ConditionalCheckFailed":
                        return "stale"
                    else:
                        raise

                if not retryable or attempt == _MAX_TRANSACTION_ATTEMPTS - 1:
                    raise

                if transaction_in_progress:
                    elapsed = time.monotonic() - first_attempt_at
                    remaining = (
                        _TRANSACTION_IN_PROGRESS_RECOVERY_SECONDS - elapsed
                    )

                    if remaining > 0:
                        time.sleep(remaining)
                else:
                    ceiling = min(
                        _TRANSACTION_BACKOFF_BASE_SECONDS * (2**attempt),
                        _TRANSACTION_BACKOFF_MAX_SECONDS,
                    )
                    time.sleep(random.uniform(0, ceiling))

        raise RuntimeError("DynamoDB transaction retry loop exited unexpectedly")
