"""Dependency preflight for stdio MCP hosts.

Most hosts (Cursor, Claude Desktop, Claude Code, VS Code, Windsurf, etc.)
mark a stdio server healthy only after the process starts and completes the
MCP handshake. If we exit(1) before mcp.run(), the host shows the server as
offline/error with our stderr message in logs.

Config shape is the common ``mcpServers`` object:
  { "mcpServers": { "wireshark": { "command", "args", "env" } } }
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

from wireshark_mcp.clients import ClientTarget, find_target, list_client_targets


DEFAULT_WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
DEFAULT_UNIX_CANDIDATES = (
    Path("/usr/bin/tshark"),
    Path("/usr/local/bin/tshark"),
    Path("/opt/homebrew/bin/tshark"),
)

DEFAULT_SERVER_KEY = "wireshark"


@dataclass
class PreflightReport:
    ok: bool
    tshark_path: Optional[str]
    tshark_version: Optional[str]
    npcape_ok: Optional[bool]
    python_ok: bool
    messages: List[str]
    install_hints: List[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _candidate_tshark_paths() -> List[Path]:
    paths: List[Path] = []
    for key in ("TSHARK_PATH", "WIRESHARK_BIN", "WIRESHARK_PATH"):
        raw = os.environ.get(key)
        if raw:
            p = Path(raw)
            if p.is_dir():
                exe = p / ("tshark.exe" if os.name == "nt" else "tshark")
                paths.append(exe)
            else:
                paths.append(p)
    which = shutil.which("tshark")
    if which:
        paths.append(Path(which))
    if os.name == "nt":
        paths.append(DEFAULT_WINDOWS_TSHARK)
    else:
        paths.extend(DEFAULT_UNIX_CANDIDATES)
    seen = set()
    out: List[Path] = []
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def resolve_tshark() -> Optional[Path]:
    for candidate in _candidate_tshark_paths():
        if candidate.is_file():
            return candidate
    return None


def tshark_version(tshark: Path) -> Optional[str]:
    try:
        proc = subprocess.run(
            [str(tshark), "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        line = (proc.stdout or proc.stderr or "").splitlines()
        return line[0].strip() if line else None
    except Exception:
        return None


def check_npcap() -> Optional[bool]:
    """Best-effort Npcap/libpcap presence. None if unknown."""
    if os.name == "nt":
        wpcap = Path(r"C:\Windows\System32\Npcap\wpcap.dll")
        wpcap2 = Path(r"C:\Windows\System32\wpcap.dll")
        return wpcap.is_file() or wpcap2.is_file()
    return True if shutil.which("tshark") or resolve_tshark() else None


def install_hints() -> List[str]:
    system = platform.system().lower()
    hints = [
        "Install Wireshark (includes TShark): https://www.wireshark.org/download.html",
        "Set env TSHARK_PATH to the full path of tshark(.exe) in your MCP host config",
        'Example env: { "TSHARK_PATH": "/usr/bin/tshark" }',
        "Then run: python -m wireshark_mcp setup",
    ]
    if system == "windows":
        hints[2] = (
            'Example env: { "TSHARK_PATH": "C:\\\\Program Files\\\\Wireshark\\\\tshark.exe" }'
        )
        hints.insert(1, "Windows live capture also needs Npcap: https://npcap.com/#download")
        hints.insert(2, "winget install --id WiresharkFoundation.Wireshark -e")
    elif system == "darwin":
        hints.insert(1, "brew install wireshark")
    else:
        hints.insert(1, "sudo apt-get install -y tshark   # Debian/Ubuntu")
    return hints


def run_preflight(*, require_npcap_for_live: bool = False) -> PreflightReport:
    messages: List[str] = []
    python_ok = sys.version_info >= (3, 10)
    if not python_ok:
        messages.append(f"Python >= 3.10 required (found {sys.version.split()[0]})")

    tshark = resolve_tshark()
    version = tshark_version(tshark) if tshark else None
    if tshark:
        messages.append(f"TShark OK: {tshark}")
        if version:
            messages.append(version)
    else:
        messages.append("TShark NOT FOUND on PATH or TSHARK_PATH")

    npcape = check_npcap()
    if os.name == "nt":
        if npcape:
            messages.append("Npcap/wpcap.dll OK (live capture available)")
        else:
            messages.append(
                "Npcap missing — offline pcap analysis may work; live capture will fail"
            )

    ok = python_ok and tshark is not None
    if require_npcap_for_live and os.name == "nt" and not npcape:
        ok = False
        messages.append("Live-capture mode requires Npcap")

    return PreflightReport(
        ok=ok,
        tshark_path=str(tshark) if tshark else None,
        tshark_version=version,
        npcape_ok=npcape,
        python_ok=python_ok,
        messages=messages,
        install_hints=[] if ok else install_hints(),
    )


def ensure_ready_or_exit() -> PreflightReport:
    """Exit process (host shows offline/error) if required deps are missing."""
    report = run_preflight()
    if report.ok:
        if report.tshark_path:
            os.environ.setdefault("TSHARK_PATH", report.tshark_path)
        return report

    print("wireshark-mcp: dependency preflight FAILED", file=sys.stderr)
    print(
        "Your MCP host will show this server as offline/error until fixed.",
        file=sys.stderr,
    )
    for msg in report.messages:
        print(f"  - {msg}", file=sys.stderr)
    print("\nInstall / configure:", file=sys.stderr)
    for hint in report.install_hints:
        print(f"  • {hint}", file=sys.stderr)
    print(
        "\nAfter installing, run:  python -m wireshark_mcp setup",
        file=sys.stderr,
    )
    sys.exit(1)


def server_entry(
    *,
    python_exe: Path,
    tshark_path: Path,
    cwd: Optional[Path] = None,
) -> dict:
    """Build one mcpServers entry (host-agnostic)."""
    entry: dict = {
        "command": str(python_exe.resolve()),
        "args": ["-m", "wireshark_mcp"],
        "env": {
            # Prefer TSHARK_PATH over mutating PATH in committed configs
            "TSHARK_PATH": str(tshark_path.resolve()),
        },
    }
    if cwd is not None:
        entry["cwd"] = str(cwd.resolve())
    return entry


def write_mcp_json(
    mcp_json_path: Path,
    *,
    python_exe: Path,
    tshark_path: Path,
    server_key: str = DEFAULT_SERVER_KEY,
    cwd: Optional[Path] = None,
) -> dict:
    """Create/update an mcpServers JSON file. Returns the full document written."""
    mcp_json_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {"mcpServers": {}}
    if mcp_json_path.is_file():
        try:
            data = json.loads(mcp_json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {"mcpServers": {}}
    servers = data.setdefault("mcpServers", {})
    servers[server_key] = server_entry(
        python_exe=python_exe, tshark_path=tshark_path, cwd=cwd
    )
    mcp_json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def format_server_snippet(
    *,
    python_exe: Path,
    tshark_path: Path,
    server_key: str = DEFAULT_SERVER_KEY,
    cwd: Optional[Path] = None,
) -> str:
    doc = {
        "mcpServers": {
            server_key: server_entry(
                python_exe=python_exe, tshark_path=tshark_path, cwd=cwd
            )
        }
    }
    return json.dumps(doc, indent=2)


def interactive_setup(*, client_id: Optional[str] = None) -> int:
    """Prompt for TShark path and write / print MCP host config."""
    print("=== wireshark-mcp setup ===")
    print("Works with any stdio MCP host (Cursor, Claude Desktop, Claude Code, etc.)\n")
    report = run_preflight()
    for msg in report.messages:
        print(f"  {msg}")

    noninteractive = client_id is not None
    tshark = resolve_tshark()
    if tshark:
        print(f"\nDetected TShark: {tshark}")
        if not noninteractive:
            use = input("Use this path? [Y/n]: ").strip().lower()
            if use in ("n", "no"):
                tshark = None
    if not tshark:
        if noninteractive:
            print(
                "TShark not found. Set TSHARK_PATH or run setup without --client.",
                file=sys.stderr,
            )
            return 1
        raw = (
            input(
                "Enter full path to tshark executable "
                "(e.g. C:\\Program Files\\Wireshark\\tshark.exe):\n> "
            )
            .strip()
            .strip('"')
        )
        if not raw:
            print("No path provided.", file=sys.stderr)
            return 1
        tshark = Path(raw)
        if not tshark.is_file():
            print(f"Not a file: {tshark}", file=sys.stderr)
            return 1

    os.environ["TSHARK_PATH"] = str(tshark.resolve())
    ver = tshark_version(tshark)
    print(f"OK: {ver or tshark}")

    targets = list_client_targets()
    target: Optional[ClientTarget] = find_target(client_id) if client_id else None
    if target is None:
        if noninteractive:
            print(f"Unknown --client {client_id!r}", file=sys.stderr)
            return 1
        print("\nWhere should we write the MCP config?")
        for i, t in enumerate(targets, 1):
            print(f"  {i}) {t.label}")
            if t.path != Path("-"):
                print(f"      → {t.path}")
        choice = input("Number [1]: ").strip() or "1"
        try:
            idx = int(choice) - 1
            target = targets[idx]
        except (ValueError, IndexError):
            print("Invalid choice.", file=sys.stderr)
            return 1

    python_exe = Path(sys.executable)
    package_root = Path(__file__).resolve().parents[2]
    snippet = format_server_snippet(
        python_exe=python_exe,
        tshark_path=tshark,
        cwd=package_root if (package_root / "pyproject.toml").is_file() else None,
    )

    if target.id == "print" or target.path == Path("-"):
        print("\nPaste this into your MCP host config:\n")
        print(snippet)
        print(
            "\nSee docs/Clients.md for file locations for Cursor, Claude, VS Code, etc."
        )
    else:
        write_mcp_json(
            target.path,
            python_exe=python_exe,
            tshark_path=tshark,
            cwd=package_root if (package_root / "pyproject.toml").is_file() else None,
        )
        print(f"\nWrote {target.path}")
        if target.notes:
            print(target.notes)

    if os.name == "nt" and not check_npcap():
        print(
            "\nNote: Npcap is not detected. Install from https://npcap.com/#download "
            "for live capture."
        )
    print("\nVerify anytime:  python -m wireshark_mcp doctor")
    return 0
