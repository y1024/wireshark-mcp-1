"""FastMCP server entrypoint for Wireshark / PyShark."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from wireshark_mcp.context import PySharkContext, default_config
from wireshark_mcp.prompts import register_prompts
from wireshark_mcp.resources import register_resources
from wireshark_mcp.tools import register_tools


@asynccontextmanager
async def pyshark_lifespan(server: FastMCP) -> AsyncIterator[PySharkContext]:
    """Initialize capture history, config, and capture directory."""
    config = default_config(capture_dir="./captures")
    os.makedirs(config["capture_dir"], exist_ok=True)
    try:
        yield PySharkContext(capture_history=[], config=config)
    finally:
        pass


mcp = FastMCP(
    "PyShark",
    dependencies=["pyshark"],  # optional legacy dep; runtime capture uses TShark
    lifespan=pyshark_lifespan,
)

register_resources(mcp)
register_prompts(mcp)
register_tools(mcp)


def main() -> None:
    """Run the MCP server over stdio (caller should run preflight first)."""
    mcp.run()


if __name__ == "__main__":
    from wireshark_mcp.preflight import ensure_ready_or_exit

    ensure_ready_or_exit()
    main()
