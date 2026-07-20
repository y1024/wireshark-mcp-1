"""Shared lifespan context for the MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PySharkContext:
    """Runtime state shared across tool calls."""

    capture_history: List[Dict[str, Any]] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)


def default_config(capture_dir: str = "./captures") -> Dict[str, Any]:
    """Build default server configuration."""
    from wireshark_mcp.preflight import resolve_tshark

    tshark = resolve_tshark()
    return {
        "default_timeout": 30,
        "capture_dir": capture_dir,
        "tshark_path": str(tshark) if tshark else None,
        "allow_simulation": False,
        "package_version": "0.2.2",
    }
