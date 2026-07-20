#!/usr/bin/env python3
"""
Backward-compatible shim for the Wireshark MCP server.

Canonical entrypoint:
    python -m wireshark_mcp
    # or
    wireshark-mcp
"""

from __future__ import annotations

from wireshark_mcp import (
    _parse_tshark_interface_line,
    list_interfaces,
    quick_capture,
    validate_capture_interface,
    validate_positive_int,
)
from wireshark_mcp.server import main, mcp

# Re-export names used by tests and older docs
__all__ = [
    "mcp",
    "main",
    "list_interfaces",
    "quick_capture",
    "validate_capture_interface",
    "validate_positive_int",
    "_parse_tshark_interface_line",
]

if __name__ == "__main__":
    from wireshark_mcp.preflight import ensure_ready_or_exit

    ensure_ready_or_exit()
    main()
