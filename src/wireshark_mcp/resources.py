"""MCP resources for version and configuration."""

from __future__ import annotations

import importlib.metadata
import json

from wireshark_mcp.context import default_config


def register_resources(mcp) -> None:
    @mcp.resource("pyshark://version")
    def get_pyshark_version() -> str:
        """Get the installed PyShark / package version information."""
        lines = []
        try:
            lines.append(f"PyShark version: {importlib.metadata.version('pyshark')}")
        except importlib.metadata.PackageNotFoundError:
            lines.append("PyShark version: Not Found")
        except Exception as exc:
            lines.append(f"Error getting PyShark version: {exc}")

        try:
            lines.append(
                f"wireshark-mcp package: {importlib.metadata.version('pyshark-mcp')}"
            )
        except importlib.metadata.PackageNotFoundError:
            from wireshark_mcp import __version__

            lines.append(f"wireshark-mcp package: {__version__} (source)")
        return "\n".join(lines)

    @mcp.resource("pyshark://config")
    def get_pyshark_config() -> str:
        """Get PyShark MCP server configuration (no simulated capture mode)."""
        return json.dumps(default_config(), indent=2)
