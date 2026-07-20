"""Wireshark / PyShark MCP server package."""

__version__ = "0.2.2"

from wireshark_mcp.interfaces import list_interfaces, parse_tshark_interface_line
from wireshark_mcp.security import validate_capture_interface, validate_positive_int
from wireshark_mcp.tools.capture import quick_capture

# Back-compat alias used by older tests/docs
_parse_tshark_interface_line = parse_tshark_interface_line

__all__ = [
    "__version__",
    "list_interfaces",
    "parse_tshark_interface_line",
    "_parse_tshark_interface_line",
    "validate_capture_interface",
    "validate_positive_int",
    "quick_capture",
]
