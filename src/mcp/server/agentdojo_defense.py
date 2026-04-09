"""TEE-MCP defense as an AgentDojo pipeline element.

Plugs TEE-MCP's AuthorizationManager into AgentDojo's agent pipeline.
Intercepts tool calls BEFORE execution and blocks unauthorized ones.

This is how TEE-MCP would defend in the AgentDojo benchmark:

  Pipeline: [SystemMessage, InitQuery, LLM, TEEMCPDefense, ToolsExecutor]
                                              ^^^^^^^^^^^^^^^^
                                        Intercepts here — before execution

Usage with AgentDojo benchmark:

    from mcp.server.agentdojo_defense import TEEMCPDefense

    defense = TEEMCPDefense(authorization_manager, subject="agent")
    pipeline = AgentPipeline([system_msg, init_query, llm, defense, tools_executor])

    # Run AgentDojo benchmark with this pipeline
    python -m agentdojo.scripts.benchmark --model gpt-4o -s banking ...
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from mcp.server.authorization import AuthorizationManager

logger = logging.getLogger(__name__)

try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
    from agentdojo.types import (
        ChatMessage,
        ChatToolResultMessage,
        text_content_block_from_string,
    )

    HAS_AGENTDOJO = True
except ImportError:
    HAS_AGENTDOJO = False


def create_defense(
    mgr: AuthorizationManager,
    subject: str = "agent",
) -> Any:
    """Create a TEE-MCP defense pipeline element for AgentDojo.

    Args:
        mgr: AuthorizationManager with registered tools and policies.
        subject: The agent identity for authorization (matched against AccessRules).

    Returns:
        A BasePipelineElement that intercepts unauthorized tool calls.

    Raises:
        ImportError: If agentdojo is not installed.
    """
    if not HAS_AGENTDOJO:
        raise ImportError("agentdojo is required for pipeline defense integration")

    class TEEMCPDefense(BasePipelineElement):
        """AgentDojo pipeline element that enforces TEE-MCP authorization.

        Sits between the LLM and ToolsExecutor in the pipeline. When the LLM
        outputs tool calls, this element checks each one against the
        AuthorizationManager. Unauthorized calls are replaced with error
        messages — the tool function NEVER executes.

        This models what happens in a real TEE-MCP deployment: the MCP Server
        (running in a TDX enclave) checks authorization before forwarding
        the tool call to the tool container.
        """

        name = "tee_mcp_defense"

        def __init__(self, authorization_manager: AuthorizationManager, agent_subject: str) -> None:
            self._mgr = authorization_manager
            self._subject = agent_subject

        def query(
            self,
            query: str,
            runtime: FunctionsRuntime,
            env: Env = EmptyEnv(),
            messages: Sequence[ChatMessage] = [],
            extra_args: dict = {},
        ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
            if len(messages) == 0:
                return query, runtime, env, messages, extra_args
            if messages[-1]["role"] != "assistant":
                return query, runtime, env, messages, extra_args
            if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
                return query, runtime, env, messages, extra_args

            # Check each tool call against authorization policy
            allowed_calls = []
            blocked_results: list[ChatToolResultMessage] = []

            for tool_call in messages[-1]["tool_calls"]:
                decision = self._mgr.authorize(self._subject, tool_call.function)

                if decision.authorized:
                    allowed_calls.append(tool_call)
                else:
                    # Block: return error message instead of executing
                    denied = ", ".join(sorted(c.value for c in decision.denied_capabilities))
                    error_msg = (
                        f"TEE-MCP Authorization Denied: tool '{tool_call.function}' "
                        f"blocked by policy. Denied capabilities: {denied}. "
                        f"Rule: {decision.matched_rule}"
                    )
                    logger.warning(
                        "Blocked tool call '%s' for subject '%s': %s",
                        tool_call.function,
                        self._subject,
                        decision.reason,
                    )
                    blocked_results.append(
                        ChatToolResultMessage(
                            role="tool",
                            content=[text_content_block_from_string("")],
                            tool_call_id=tool_call.id,
                            tool_call=tool_call,
                            error=error_msg,
                        )
                    )

            # Rewrite the assistant message to only contain allowed calls
            if blocked_results:
                new_last_message = {**messages[-1], "tool_calls": allowed_calls if allowed_calls else None}
                new_messages = [*messages[:-1], new_last_message, *blocked_results]
                return query, runtime, env, new_messages, extra_args

            return query, runtime, env, messages, extra_args

    return TEEMCPDefense(mgr, subject)
