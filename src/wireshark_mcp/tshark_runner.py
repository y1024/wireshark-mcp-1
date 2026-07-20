"""Safe TShark subprocess helpers — always argv + shell=False."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence


@dataclass
class TsharkResult:
    returncode: int
    stdout: str
    stderr: str


def tshark_executable() -> str:
    """Resolve tshark binary (TSHARK_PATH / PATH / platform defaults)."""
    from wireshark_mcp.preflight import resolve_tshark

    resolved = resolve_tshark()
    if resolved is not None:
        return str(resolved)
    which = shutil.which("tshark")
    if which:
        return which
    raise FileNotFoundError(
        "tshark not found. Install Wireshark/TShark or set TSHARK_PATH, "
        "then run: python -m wireshark_mcp setup"
    )


def run_tshark(
    args: Sequence[str],
    *,
    timeout: Optional[float] = None,
) -> TsharkResult:
    """Run tshark with an argument list (never a shell string)."""
    cmd = [tshark_executable(), *list(args)]
    completed = subprocess.run(
        cmd,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    return TsharkResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def popen_tshark_capture(
    args: Sequence[str],
    *,
    wait_seconds: float,
) -> TsharkResult:
    """Start tshark, wait up to wait_seconds, then terminate if still running."""
    cmd = [tshark_executable(), *list(args)]
    process = subprocess.Popen(
        cmd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    start = time.time()
    while process.poll() is None and time.time() - start < wait_seconds:
        time.sleep(0.1)
    if process.poll() is None:
        process.terminate()
    try:
        stdout_b, stderr_b = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout_b, stderr_b = process.communicate()
    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")
    return TsharkResult(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
    )


def capture_to_pcap(
    interface: str,
    output_pcap: str,
    *,
    duration: int,
    packet_count: Optional[int] = None,
    capture_filter: str = "",
) -> TsharkResult:
    """Capture live traffic to a pcap file using argv-only tshark."""
    args: List[str] = [
        "-i",
        interface,
        "-w",
        output_pcap,
        "-a",
        f"duration:{duration}",
    ]
    if packet_count is not None:
        args.extend(["-c", str(packet_count)])
    if capture_filter:
        args.extend(["-f", capture_filter])
    return run_tshark(args, timeout=duration + 20)


def capture_to_temp_pcap(
    interface: str,
    temp_pcap: str,
    *,
    duration: int,
    packet_count: Optional[int] = None,
    capture_filter: str = "",
) -> TsharkResult:
    """Alias for capture_to_pcap (temp or permanent path)."""
    return capture_to_pcap(
        interface,
        temp_pcap,
        duration=duration,
        packet_count=packet_count,
        capture_filter=capture_filter,
    )


def read_pcap_fields(
    pcap_path: str,
    fields: Sequence[str],
    *,
    display_filter: str = "",
    timeout: float = 60,
) -> TsharkResult:
    """Read a pcap and emit tab-separated field values."""
    args: List[str] = ["-r", pcap_path, "-T", "fields"]
    if display_filter:
        args.extend(["-Y", display_filter])
    for field in fields:
        args.extend(["-e", field])
    return run_tshark(args, timeout=timeout)


def extract_stats_section(text: str, marker: str) -> str:
    """Keep only the tshark statistics block after a marker, if present."""
    if not text:
        return ""
    idx = text.find(marker)
    if idx >= 0:
        return text[idx:].strip()
    # Sometimes printed to stderr with different casing
    lower = text.lower()
    m = marker.lower()
    idx = lower.find(m)
    if idx >= 0:
        return text[idx:].strip()
    return text.strip()
