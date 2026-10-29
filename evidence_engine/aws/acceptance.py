
"""DynamoDB-backed acceptance state for shared replay detection."""

from __future__ import annotations

import re
from typing import Any, Literal


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
AcceptanceOutcome = Literal["accepted", "replay", "stale"]


class DynamoDBAcceptanceState:
    """Atomically record accepted bundle digests in a DynamoDB table.

    The supplied DynamoDB client must be a boto3 low-level client.
    The table must have a string partition key named ``bundle_digest``.
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
        if not isinstance(bundle_digest, str) or not _DIGEST_RE.fullmatch(bundle_digest):
            raise ValueError("Invalid bundle digest")
        if not isinstance(consumer_id, str) or not _IDENTIFIER_RE.fullmatch(consumer_id):
            raise ValueError("Invalid consumer ID")
        if not isinstance(stream_id, str) or not _IDENTIFIER_RE.fullmatch(stream_id):
            raise ValueError("Invalid stream ID")

        for name, value in (("run_number", run_number), ("run_attempt", run_attempt)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"Invalid {name}")

        transact = getattr(self._client, "transact_write_items", None)
        if not callable(transact):
            raise TypeError("client must provide transact_write_items")

        digest_item = {
            "pk": {"S": f"CONSUMER#{consumer_id}"},
            "sk": {"S": f"DIGEST#{bundle_digest}"},
            "record_type": {"S": "DIGEST"},
            "bundle_digest": {"S": bundle_digest},
            "stream_id": {"S": stream_id},
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
            ]
        }

        try:
            transact(**request)
        except Exception as exc:
            response = getattr(exc, "response", None)
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            if not isinstance(error, dict) or error.get("Code") != "TransactionCanceledException":
                raise

            reasons = response.get("CancellationReasons", [])
            if not isinstance(reasons, list) or len(reasons) != 2:
                raise

            codes = [
                item.get("Code") if isinstance(item, dict) else None
                for item in reasons
            ]
            if codes[0] == "ConditionalCheckFailed":
                return "replay"
            if codes[1] == "ConditionalCheckFailed":
                return "stale"
            raise

        return "accepted"
