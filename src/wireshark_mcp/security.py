"""Input validation for capture tools (CWE-78 / path traversal hardening)."""

from __future__ import annotations

import os
import re
from typing import Any, Optional, Tuple

from wireshark_mcp.interfaces import list_interfaces

FORBIDDEN_INTERFACE_CHARS = set(';"\'`$|&<>\n\r\0')
# Shell / control chars never allowed in filters or paths
FORBIDDEN_CONTROL = set("\n\r\0`;$\\")
SAFE_BPF_RE = re.compile(r"^[A-Za-z0-9\s()\[\]=<>!&|.\-:/,_*%]+$")
SAFE_DISPLAY_RE = re.compile(r'^[A-Za-z0-9\s()\[\]=<>!&|.\-:/,_*%"\']+$')
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")
PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")


def validate_capture_interface(interface: str) -> Optional[str]:
    """
    Allow only exact matches against currently enumerated local interfaces.

    Rejects shell-metacharacter payloads used for command injection.
    """
    if not isinstance(interface, str):
        return None
    interface = interface.strip()
    if not interface:
        return None

    if any(ch in interface for ch in FORBIDDEN_INTERFACE_CHARS):
        return None

    if interface in set(list_interfaces()):
        return interface
    return None


def invalid_interface_message() -> str:
    return (
        "Error: invalid or unauthorized interface. "
        "Use list_interfaces and pass an exact interface name."
    )


def validate_positive_int(
    value: Any,
    *,
    default: int,
    minimum: int = 1,
    maximum: int = 3600,
) -> int:
    """Coerce and clamp integer tool arguments."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def validate_bpf_filter(capture_filter: str) -> Tuple[Optional[str], Optional[str]]:
    """Validate a BPF capture filter (-f). Empty string is allowed."""
    if capture_filter is None:
        return "", None
    if not isinstance(capture_filter, str):
        return None, "Error: capture_filter must be a string"
    capture_filter = capture_filter.strip()
    if not capture_filter:
        return "", None
    if len(capture_filter) > 512:
        return None, "Error: capture_filter too long"
    if any(ch in capture_filter for ch in FORBIDDEN_CONTROL):
        return None, "Error: capture_filter contains forbidden characters"
    if not SAFE_BPF_RE.match(capture_filter):
        return None, "Error: capture_filter contains unsupported characters"
    return capture_filter, None


def validate_display_filter(display_filter: str) -> Tuple[Optional[str], Optional[str]]:
    """Validate a Wireshark display filter (-Y). Empty string is allowed."""
    if display_filter is None:
        return "", None
    if not isinstance(display_filter, str):
        return None, "Error: display_filter must be a string"
    display_filter = display_filter.strip()
    if not display_filter:
        return "", None
    if len(display_filter) > 512:
        return None, "Error: display_filter too long"
    if any(ch in display_filter for ch in FORBIDDEN_CONTROL):
        return None, "Error: display_filter contains forbidden characters"
    if not SAFE_DISPLAY_RE.match(display_filter):
        return None, "Error: display_filter contains unsupported characters"
    return display_filter, None


def validate_target_host(host: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Validate optional host for targeted capture."""
    if host is None or host == "":
        return None, None
    if not isinstance(host, str):
        return None, "Error: target_host must be a string"
    host = host.strip()
    if len(host) > 253 or not SAFE_HOST_RE.match(host):
        return None, "Error: invalid target_host"
    return host, None


def validate_pcap_read_path(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve and validate an existing pcap path for reading."""
    if not isinstance(file_path, str) or not file_path.strip():
        return None, "Error: file path is required"
    if any(ch in file_path for ch in "\n\r\0"):
        return None, "Error: invalid file path"
    path = os.path.abspath(os.path.expanduser(file_path.strip()))
    if not path.lower().endswith(PCAP_SUFFIXES):
        return None, "Error: file must be a .pcap, .pcapng, or .cap capture"
    if not os.path.isfile(path):
        return None, f"Error: Capture file not found: {path}"
    return path, None


def validate_pcap_write_path(
    file_path: str,
    *,
    captures_dir: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate output pcap path.

    Relative paths are resolved under captures_dir when provided.
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return None, "Error: output_file is required"
    if any(ch in file_path for ch in "\n\r\0"):
        return None, "Error: invalid output_file"
    raw = file_path.strip()
    if not os.path.isabs(raw):
        base = os.path.abspath(captures_dir or "./captures")
        # Block path traversal out of captures_dir for relative inputs
        candidate = os.path.abspath(os.path.join(base, raw))
        if not candidate.startswith(base + os.sep) and candidate != base:
            return None, "Error: output_file escapes captures directory"
        path = candidate
    else:
        path = os.path.abspath(raw)

    if not path.lower().endswith(PCAP_SUFFIXES):
        return None, "Error: output_file must end with .pcap, .pcapng, or .cap"

    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            return None, f"Error: cannot create output directory: {exc}"
    return path, None
