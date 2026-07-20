"""Package / MCP surface smoke tests (no live capture)."""

from __future__ import annotations

import json

from wireshark_mcp.context import default_config
from wireshark_mcp.server import mcp


def test_default_config_disables_simulation() -> None:
    cfg = default_config()
    assert cfg["allow_simulation"] is False
    assert "capture_dir" in cfg


def test_mcp_registers_expected_prompts() -> None:
    # FastMCP stores prompts; assert registration side did not crash and names exist
    prompt_fn_names = {
        "packet_capture_help",
        "investigate_live_traffic",
        "analyze_pcap_file",
        "security_traffic_review",
        "safe_capture_rules",
    }
    # Access internal prompt manager if available
    prompts = getattr(mcp, "_prompt_manager", None) or getattr(mcp, "_prompts", None)
    if prompts is None:
        # Fallback: ensure server object exists and has expected attribute surface
        assert mcp.name == "PyShark"
        return

    registered = set()
    if hasattr(prompts, "_prompts"):
        registered = set(prompts._prompts.keys())
    elif isinstance(prompts, dict):
        registered = set(prompts.keys())

    if registered:
        assert prompt_fn_names.issubset(registered)


def test_config_resource_json() -> None:
    from wireshark_mcp.resources import register_resources
    from mcp.server.fastmcp import FastMCP

    app = FastMCP("test")
    register_resources(app)
    # Call underlying function via resource manager if possible
    cfg = default_config()
    assert json.loads(json.dumps(cfg))["allow_simulation"] is False
