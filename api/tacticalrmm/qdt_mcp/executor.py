"""Synchronous executor for the MCP tools exposed by qdt_mcp.server.

This module lets Django views run MCP tools without making an HTTP round-trip
to /mcp. Callers pass their requesting user: the tool then runs with that user's
API key forwarded to the trmm REST layer, so role permissions and client/site
scoping apply exactly as if the user had called the API directly. The calling
view is still responsible for authentication, audit logging and rate limiting.
"""

from __future__ import annotations

import inspect
from typing import Any

from asgiref.sync import async_to_sync
from django.utils.crypto import get_random_string

from accounts.models import APIKey
from qdt_mcp.server import _api_key, mcp

# one reusable API key per user, so the AI chat's tool calls hit the trmm REST
# layer with exactly that user's permissions and client/site scoping
AI_CHAT_KEY_PREFIX = "ai-chat-"


def _api_key_for(user) -> str:
    key_obj, _ = APIKey.objects.get_or_create(
        name=f"{AI_CHAT_KEY_PREFIX}{user.pk}",
        defaults={"key": get_random_string(length=32).upper(), "user": user},
    )
    return key_obj.key


def _tool_meta() -> dict[str, dict[str, Any]]:
    """Return a dict of tool metadata keyed by tool name."""
    # FastMCP (mcp package) keeps registered tools in _tool_manager._tools
    return {
        name: {
            "description": tool.description,
            "callable": tool.fn,
            "parameters": tool.parameters,
            "annotations": getattr(tool, "annotations", None),
        }
        for name, tool in mcp._tool_manager._tools.items()
    }


def list_mcp_tools() -> list[dict[str, Any]]:
    """Return a JSON-serializable list of all MCP tools with their schemas."""
    tools = []
    for name, meta in _tool_meta().items():
        annotations = meta["annotations"]
        tool_info: dict[str, Any] = {
            "name": name,
            "description": meta["description"],
            "parameters": meta["parameters"],
            "read_only": bool(
                annotations and getattr(annotations, "readOnlyHint", False)
            ),
            "destructive": bool(
                annotations and getattr(annotations, "destructiveHint", False)
            ),
        }
        tools.append(tool_info)
    return tools


def is_read_only_tool(name: str) -> bool:
    """Return True if the named tool is annotated as read-only."""
    meta = _tool_meta().get(name)
    if not meta:
        return False
    annotations = meta["annotations"]
    return bool(annotations and getattr(annotations, "readOnlyHint", False))


def _call_as_user(fn, arguments: dict[str, Any], user) -> Any:
    """Run a tool with the _api_key contextvar bound to this user's key.

    The key is set inside the coroutine rather than around async_to_sync, so it
    does not depend on context propagation across the event loop thread.
    """
    key = _api_key_for(user)

    if inspect.iscoroutinefunction(fn):

        async def run():
            token = _api_key.set(key)
            try:
                return await fn(**arguments)
            finally:
                _api_key.reset(token)

        return async_to_sync(run)()

    token = _api_key.set(key)
    try:
        return fn(**arguments)
    finally:
        _api_key.reset(token)


def execute_mcp_tool(
    name: str, arguments: dict[str, Any] | None = None, user=None
) -> Any:
    """Execute an MCP tool by name and return its result.

    With `user`, the tool runs as that user: its API key is forwarded to the trmm
    REST layer, which then enforces their role permissions and scoping. Without
    it the tool runs keyless and will fail on any authenticated endpoint.
    The call is wrapped in a try/except so failures return as structured errors
    instead of raising through the view.
    """
    arguments = arguments or {}
    meta = _tool_meta().get(name)
    if not meta:
        return {"ok": False, "error": f"Unknown tool: {name}"}

    fn = meta["callable"]
    try:
        if user is not None:
            result = _call_as_user(fn, arguments, user)
        elif inspect.iscoroutinefunction(fn):
            result = async_to_sync(fn)(**arguments)
        else:
            result = fn(**arguments)
        return {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
