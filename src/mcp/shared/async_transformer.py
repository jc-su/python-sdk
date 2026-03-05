"""
Async request/response transformers for ASGI middleware.

Provides utilities to intercept and transform HTTP requests and responses
in an ASGI application. Used by TEE transport to modify initialize
handshake and encrypt/decrypt messages.
"""

import logging
from collections.abc import AsyncGenerator, Awaitable
from typing import Literal, Protocol

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Send

logger = logging.getLogger(__name__)

__all__ = [
    "RequestTransformer",
    "ResponseTransformer",
    "ResponseTransformerInterface",
    "TransformAction",
]


class RequestTransformer:
    """
    Collects and transforms HTTP request body.

    Buffers the entire request body for inspection/modification,
    then replays it when the application reads the request.
    """

    upstream: Receive
    messages: list[Message]
    body: bytes
    _channel: AsyncGenerator[Message, None]

    def __init__(self, upstream: Receive):
        self.upstream = upstream
        self.messages = []
        self.body = b""
        self._channel = self._loop()

    async def collect_body(self) -> None:
        """Read and buffer the entire request body."""
        while True:
            message = await self.upstream()
            if message["type"] == "http.request":
                self.body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            else:
                self.messages.append(message)
                if message["type"] == "http.disconnect":
                    break

    async def _loop(self) -> AsyncGenerator[Message, None]:
        """Generate messages: replay buffered, then forward upstream."""
        # Replay received messages
        for message in self.messages:
            yield message
        yield {"type": "http.request", "body": self.body, "more_body": False}

        # Forward to upstream
        while True:
            yield await self.upstream()

    def receive(self) -> Awaitable[Message]:
        """ASGI receive callable that replays/forwards messages."""
        return anext(self._channel)


TransformAction = Literal["pass", "transform_full", "transform_line"]


class ResponseTransformerInterface(Protocol):
    """Protocol for response transformation strategies."""

    def headers(self, status: int, headers: MutableHeaders) -> TransformAction:
        """
        Inspect response headers and decide transformation action.

        Args:
            status: HTTP status code
            headers: Mutable response headers (can be modified)

        Returns:
            "pass" - no transformation, forward as-is
            "transform_full" - collect full body then transform
            "transform_line" - transform line-by-line (for SSE)
        """
        return "pass"

    def transform_full(self, body: bytes) -> bytes:
        """Transform the complete response body."""
        return body

    def transform_line(self, line: bytes) -> bytes:
        """Transform a single line of SSE response."""
        return line


class ResponseTransformer:
    """
    Transforms HTTP response headers and body.

    Wraps the ASGI send callable to intercept and transform
    response messages according to the transformer interface.
    """

    downstream: Send
    transformer: ResponseTransformerInterface
    _channel: AsyncGenerator[None, Message] | None

    def __init__(self, downstream: Send, transformer: ResponseTransformerInterface):
        self.downstream = downstream
        self.transformer = transformer
        self._channel = None

    async def _loop(self) -> AsyncGenerator[None, Message]:
        """Process response messages with transformation."""
        while True:
            # Start of a response
            message = yield

            # Expect response headers
            if message["type"] != "http.response.start":
                logger.warning(f"Expecting headers message, got {message['type']}")
                await self.downstream(message)
                continue

            # Determine action from transformer
            status = message.get("status", 0)
            headers = MutableHeaders(raw=list(message.get("headers", [])))

            action = self.transformer.headers(status, headers)

            # Handler may have changed headers
            message["headers"] = headers.raw

            if action == "pass":
                await self._passthrough(message)
            elif action == "transform_full":
                await self._transform_full(message, headers)
            elif action == "transform_line":
                await self._transform_line(message)

    async def _passthrough(self, headers_message: Message) -> None:
        """Pass response through without transformation."""
        await self.downstream(headers_message)
        more_body = True
        while more_body:
            message = yield  # type: ignore[misc]
            if message["type"] != "http.response.body":
                logger.warning(f"Expecting body message, got {message['type']}")
                await self.downstream(message)
                break
            await self.downstream(message)
            more_body = message.get("more_body", False)

    async def _transform_full(
        self, headers_message: Message, headers: MutableHeaders
    ) -> None:
        """Collect full body, transform, then send."""
        # Defer sending headers until we have full body
        body = b""
        more_body = True
        while more_body:
            message = yield  # type: ignore[misc]
            if message["type"] != "http.response.body":
                logger.warning(f"Expecting body message, got {message['type']}")
                await self.downstream(message)
                break
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        body = self.transformer.transform_full(body)

        # Send updated headers with correct content-length
        headers["content-length"] = str(len(body))
        headers_message["headers"] = headers.raw
        await self.downstream(headers_message)

        # Send transformed body
        await self.downstream(
            {"type": "http.response.body", "body": body, "more_body": False}
        )

    async def _transform_line(self, headers_message: Message) -> None:
        """Transform response line-by-line (for SSE streams)."""
        await self.downstream(headers_message)
        body = b""
        more_body = True
        while more_body:
            message = yield  # type: ignore[misc]
            if message["type"] != "http.response.body":
                logger.warning(f"Expecting body message, got {message['type']}")
                await self.downstream(message)
                break
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

            lines = b""
            while True:
                idx = body.find(b"\n")
                if idx == -1:
                    break
                line = body[:idx]
                sep = b"\n"
                if line.endswith(b"\r"):
                    line = line[:-1]
                    sep = b"\r\n"
                body = body[idx + 1 :]
                lines += self.transformer.transform_line(line)
                lines += sep

            if not more_body or lines:
                message["body"] = lines
                await self.downstream(message)

        if body:
            logger.warning("Response body not ending in newline")

    async def send(self, message: Message) -> None:
        """ASGI send callable that transforms responses."""
        if self._channel is None:
            self._channel = self._loop()
            await anext(self._channel)  # Run to first yield
        await self._channel.asend(message)
