"""Environment / setup MCP tools."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from mcp.server.fastmcp import Context

from wireshark_mcp.preflight import (
    install_hints,
    resolve_tshark,
    run_preflight,
    tshark_version,
    write_mcp_json,
)


def _find_mcp_json() -> Path | None:
    for candidate in (
        Path.cwd() / ".cursor" / "mcp.json",
        Path.cwd().parent / ".cursor" / "mcp.json",
    ):
        if candidate.is_file() or candidate.parent.is_dir():
            return candidate
    return None


def register(mcp) -> None:
    @mcp.tool(name="check_environment")
    def check_environment() -> str:
        """
        Report whether TShark/Npcap are installed and configured.

        If this server is online in your MCP host, TShark was found at startup.
        Use configure_tshark if you need to set a custom path.
        """
        report = run_preflight()
        lines = ["wireshark-mcp environment check", "=============================="]
        lines.extend(f"- {m}" for m in report.messages)
        lines.append(f"- ready_for_mcp: {report.ok}")
        if report.tshark_path:
            lines.append(f"- TSHARK_PATH: {report.tshark_path}")
        if not report.ok:
            lines.append("\nInstall / configure:")
            lines.extend(f"  • {h}" for h in report.install_hints)
            lines.append("\nOr run in a terminal: python -m wireshark_mcp setup")
        return "\n".join(lines)

    @mcp.tool(name="configure_tshark")
    async def configure_tshark(
        tshark_path: str = "",
        ctx: Context = None,
    ) -> str:
        """
        Configure the TShark binary path for this MCP server.

        Pass tshark_path explicitly (recommended). If empty, may elicit a form
        when the client supports MCP elicitation. After changing path, reload
        the MCP server in your host so preflight re-runs.
        """
        path = (tshark_path or "").strip().strip('"')

        if not path and ctx is not None:
            elicit = getattr(ctx, "elicit", None)
            if callable(elicit):
                try:
                    result = await elicit(
                        message=(
                            "Enter the full path to tshark "
                            r"(e.g. C:\Program Files\Wireshark\tshark.exe)."
                        ),
                        requested_schema={
                            "type": "object",
                            "properties": {
                                "tshark_path": {
                                    "type": "string",
                                    "title": "TShark executable path",
                                    "description": "Full path to tshark or tshark.exe",
                                }
                            },
                            "required": ["tshark_path"],
                        },
                    )
                    if isinstance(result, dict):
                        action = result.get("action", "accept")
                        content = result.get("content") or {}
                        if action == "accept":
                            path = str(content.get("tshark_path", "")).strip()
                    elif hasattr(result, "action") and str(result.action) in (
                        "accept",
                        "Accept",
                    ):
                        content = getattr(result, "content", None) or {}
                        if isinstance(content, dict):
                            path = str(content.get("tshark_path", "")).strip()
                except Exception as exc:
                    return (
                        "Could not open an interactive prompt "
                        f"({type(exc).__name__}: {exc}).\n"
                        "Run in a terminal instead:\n"
                        "  python -m wireshark_mcp setup\n\n"
                        + "\n".join(f"• {h}" for h in install_hints())
                    )

        if not path:
            detected = resolve_tshark()
            if detected:
                return (
                    f"TShark already detected at:\n  {detected}\n"
                    f"Version: {tshark_version(detected) or 'unknown'}\n\n"
                    "To override, call configure_tshark with tshark_path=..., "
                    "or run: python -m wireshark_mcp setup"
                )
            return (
                "No TShark path provided and none detected.\n\n"
                + "\n".join(f"• {h}" for h in install_hints())
            )

        exe = Path(path)
        if exe.is_dir():
            exe = exe / ("tshark.exe" if os.name == "nt" else "tshark")
        if not exe.is_file():
            return f"Error: not a file: {exe}"

        os.environ["TSHARK_PATH"] = str(exe.resolve())
        ver = tshark_version(exe)

        written = None
        target = _find_mcp_json()
        if target is not None:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                write_mcp_json(
                    target,
                    python_exe=Path(sys.executable),
                    tshark_path=exe,
                )
                written = target
            except Exception:
                written = None

        lines = [
            f"Configured TSHARK_PATH={exe.resolve()}",
            f"Version: {ver or 'unknown'}",
        ]
        if written:
            lines.append(f"Updated mcp.json: {written}")
            lines.append("Reload/restart the MCP server in your host to apply.")
        else:
            escaped = str(exe.resolve()).replace("\\", "\\\\")
            lines.append(
                "Add to mcp.json env:\n"
                f'  "TSHARK_PATH": "{escaped}"'
            )
        return "\n".join(lines)
