"""Synchronous executor for the MCP tools exposed by qdt_mcp.server.

This module lets Django views run MCP tools without making an HTTP round-trip
to /mcp and without requiring an X-API-KEY. The calling view is responsible for
authentication, authorization, audit logging and rate limiting.
"""

from __future__ import annotations

import inspect
from typing import Any

from asgiref.sync import async_to_sync

from qdt_mcp.server import mcp


def _tool_meta() -> dict[str, dict[str, Any]]:
    """Return a dict of tool metadata keyed by tool name."""
    # FastMCP stores registered tools in _tools as Tool objects
    return {
        name: {
            "description": tool.description,
            "callable": tool.callable,
            "parameters": tool.parameters,
            "annotations": getattr(tool, "annotations", None),
        }
        for name, tool in mcp._tools.items()
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


def execute_mcp_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Execute an MCP tool by name and return its result.

    The tool call is wrapped in a try/except so that failures are returned as
    structured errors instead of raising through the view.
    """
    arguments = arguments or {}
    meta = _tool_meta().get(name)
    if not meta:
        return {"ok": False, "error": f"Unknown tool: {name}"}

    fn = meta["callable"]
    try:
        if inspect.iscoroutinefunction(fn):
            result = async_to_sync(fn)(**arguments)
        else:
            result = fn(**arguments)
        return {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
