"""Known MCP client config locations (stdio mcpServers schema)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class ClientTarget:
    """A place where an MCP host reads mcpServers JSON."""

    id: str
    label: str
    path: Path
    notes: str = ""


def _home() -> Path:
    return Path.home()


def cursor_project_mcp_json(start: Optional[Path] = None) -> Path:
    cwd = (start or Path.cwd()).resolve()
    # Prefer parent workspace if we are inside the clone folder
    if cwd.name == "wireshark-mcp" and (cwd.parent / ".cursor").is_dir():
        return cwd.parent / ".cursor" / "mcp.json"
    return cwd / ".cursor" / "mcp.json"


def claude_desktop_config_path() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
        return _home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    if sys_platform_is_darwin():
        return (
            _home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    return _home() / ".config" / "Claude" / "claude_desktop_config.json"


def sys_platform_is_darwin() -> bool:
    import sys

    return sys.platform == "darwin"


def claude_code_user_path() -> Path:
    return _home() / ".claude.json"


def claude_code_project_path(start: Optional[Path] = None) -> Path:
    return (start or Path.cwd()).resolve() / ".mcp.json"


def vscode_mcp_json(start: Optional[Path] = None) -> Path:
    return (start or Path.cwd()).resolve() / ".vscode" / "mcp.json"


def list_client_targets(start: Optional[Path] = None) -> List[ClientTarget]:
    """Presets a novice can pick during setup."""
    return [
        ClientTarget(
            id="print",
            label="Print JSON only (copy into any MCP host)",
            path=Path("-"),
            notes="Works with any stdio MCP client that uses mcpServers.",
        ),
        ClientTarget(
            id="example",
            label="Write examples/mcp.local.json in this repo",
            path=(start or Path.cwd()).resolve() / "examples" / "mcp.local.json",
            notes="Safe local file; add it to your client manually.",
        ),
        ClientTarget(
            id="cursor",
            label="Cursor (project .cursor/mcp.json)",
            path=cursor_project_mcp_json(start),
            notes="Reload MCP / window after writing.",
        ),
        ClientTarget(
            id="claude-desktop",
            label="Claude Desktop",
            path=claude_desktop_config_path(),
            notes="Fully quit and reopen Claude Desktop after writing.",
        ),
        ClientTarget(
            id="claude-code-user",
            label="Claude Code (user ~/.claude.json)",
            path=claude_code_user_path(),
            notes="Restart Claude Code / reload MCP after writing.",
        ),
        ClientTarget(
            id="claude-code-project",
            label="Claude Code (project .mcp.json)",
            path=claude_code_project_path(start),
            notes="Project-scoped MCP for Claude Code.",
        ),
        ClientTarget(
            id="vscode",
            label="VS Code / Copilot (.vscode/mcp.json)",
            path=vscode_mcp_json(start),
            notes="Schema may wrap servers; see docs/Clients.md.",
        ),
    ]


def find_target(client_id: str, start: Optional[Path] = None) -> Optional[ClientTarget]:
    for t in list_client_targets(start):
        if t.id == client_id:
            return t
    return None
