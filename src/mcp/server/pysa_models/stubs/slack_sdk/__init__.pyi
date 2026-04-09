"""Minimal type stubs for slack_sdk — enables Pysa sink resolution."""

from typing import Any

class WebClient:
    def chat_postMessage(self, channel: str, text: str, **kwargs: Any) -> Any: ...
