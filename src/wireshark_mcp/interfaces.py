"""Network interface enumeration via TShark."""

from __future__ import annotations

import re
from typing import List

from wireshark_mcp.tshark_runner import run_tshark


def parse_tshark_interface_line(line: str) -> List[str]:
    """Parse one `tshark -D` line into friendly and/or device names."""
    line = line.strip()
    if not line:
        return []

    skip_markers = ("ciscodump", "randpkt", "sshdump", "udpdump", "wifidump")
    if any(marker in line.lower() for marker in skip_markers):
        return []

    if ". " in line:
        line = line.split(". ", 1)[1]

    names: List[str] = []
    match = re.match(r"^(.+?) \((.+)\)\s*$", line)
    if match:
        device_id = match.group(1).strip()
        friendly_name = match.group(2).strip()
        if friendly_name:
            names.append(friendly_name)
        if device_id and device_id != friendly_name:
            names.append(device_id)
    else:
        names.append(line.strip())
    return names


def list_interfaces() -> List[str]:
    """Return available local capture interface names."""
    try:
        result = run_tshark(["-D"], timeout=30)
        if result.returncode != 0 and not result.stdout:
            return []

        interfaces: List[str] = []
        seen = set()
        for line in result.stdout.strip().split("\n"):
            for name in parse_tshark_interface_line(line):
                if name not in seen:
                    seen.add(name)
                    interfaces.append(name)
        return interfaces
    except Exception as exc:
        print(f"Error listing interfaces: {exc}")
        return []
