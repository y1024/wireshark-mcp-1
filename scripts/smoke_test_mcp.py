#!/usr/bin/env python3
"""Smoke-test Wireshark MCP tool functions against the local machine."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from wireshark_mcp import list_interfaces, quick_capture  # noqa: E402
from wireshark_mcp.context import default_config  # noqa: E402
from wireshark_mcp.server import mcp  # noqa: E402


def pick_interface(interfaces: list[str]) -> str | None:
    preferred = ("Wi-Fi", "Ethernet", "eth0", "en0")
    for name in preferred:
        if name in interfaces:
            return name
    for iface in interfaces:
        if not iface.startswith("\\Device\\") and "dump" not in iface.lower():
            return iface
    return interfaces[0] if interfaces else None


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    tools = mcp._tool_manager._tools
    prompts = mcp._prompt_manager._prompts

    section("surface")
    print("tools:", len(tools))
    print("prompts:", sorted(prompts.keys()))
    print("config:", json.dumps(default_config(), indent=2))

    section("list_interfaces")
    interfaces = list_interfaces()
    print(json.dumps(interfaces[:8], indent=2), "...")
    iface = pick_interface(interfaces)
    print(f"Using interface: {iface}")
    if not iface:
        print("No usable interface; aborting live tests.")
        return 1

    section("quick_capture")
    print(quick_capture(interface=iface, duration=2, packet_limit=5))

    section("quick_traffic_analysis")
    print(tools["quick_traffic_analysis"].fn(iface, 2, 5))

    section("read_pcap_file")
    pcap = os.path.join(tempfile.gettempdir(), f"mcp_smoke_{int(time.time())}.pcap")
    subprocess.run(
        ["tshark", "-i", iface, "-c", "3", "-a", "duration:3", "-w", pcap],
        shell=False,
        check=False,
    )
    if os.path.exists(pcap) and os.path.getsize(pcap) > 0:
        print(tools["read_pcap_file"].fn(pcap))
    else:
        print("Skip: empty pcap dump")

    section("SUMMARY")
    print("OK — reload Cursor MCP to pick up prompts; project skill is under .cursor/skills/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
