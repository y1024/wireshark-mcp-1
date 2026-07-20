"""MCP tool registrations."""

from wireshark_mcp.tools import analysis, capture, diagnostics, environment, http_dns


def register_tools(mcp) -> None:
    """Register all tools on the FastMCP instance."""
    environment.register(mcp)
    capture.register(mcp)
    analysis.register(mcp)
    http_dns.register(mcp)
    diagnostics.register(mcp)
