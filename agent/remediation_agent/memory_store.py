# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Long-term memory of successful fixes, backed by Amazon Bedrock AgentCore Memory.

A semantic memory strategy extracts reusable facts ("upgrading jinja2 to 3.x
requires replacing jinja2.Markup with markupsafe.Markup") from the fix
summaries that the agent records, so later runs in other repositories can
retrieve them.
"""

from __future__ import annotations

import logging

ACTOR_ID = "dependency-remediation-agent"
NAMESPACE = f"remediation/{ACTOR_ID}"

log = logging.getLogger(__name__)


class FixMemory:
    def __init__(self, memory_id: str | None, region: str):
        self.memory_id = memory_id
        self._client = None
        if memory_id:
            from bedrock_agentcore.memory import MemoryClient

            self._client = MemoryClient(region_name=region)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def recall(self, query: str, top_k: int = 5) -> list[str]:
        if not self._client:
            return []
        try:
            records = self._client.retrieve_memories(memory_id=self.memory_id, namespace=NAMESPACE, query=query, top_k=top_k)
        except Exception:  # memory is an optimization; never fail a run because of it
            log.exception("Memory retrieval failed")
            return []
        return [r.get("content", {}).get("text", "") for r in records if r.get("content", {}).get("text")]

    def remember(self, session_id: str, task: str, outcome: str) -> None:
        if not self._client:
            return
        try:
            self._client.create_event(
                memory_id=self.memory_id,
                actor_id=ACTOR_ID,
                session_id=session_id,
                messages=[(task, "USER"), (outcome, "ASSISTANT")],
            )
        except Exception:
            log.exception("Memory write failed")
