# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Run records in Amazon DynamoDB. Every run is recorded, including failures."""

from __future__ import annotations

import logging
import time
from decimal import Decimal

log = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, table_name: str | None, region: str):
        self._table = None
        if table_name:
            import boto3

            self._table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def update(self, run_id: str, **fields) -> None:
        if not self._table:
            log.info("audit %s %s", run_id, fields)
            return
        fields["updated_at"] = int(time.time())
        clean = {k: (Decimal(str(v)) if isinstance(v, float) else v) for k, v in fields.items() if v is not None}
        names = {f"#{k}": k for k in clean}
        values = {f":{k}": v for k, v in clean.items()}
        expression = "SET " + ", ".join(f"#{k} = :{k}" for k in clean)
        try:
            self._table.update_item(
                Key={"pk": f"run#{run_id}"},
                UpdateExpression=expression,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except Exception:
            log.exception("Failed to write audit record for %s", run_id)
