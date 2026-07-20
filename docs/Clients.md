# MCP clients

This server speaks **stdio MCP**. Any host that can launch a local process with:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "wireshark_mcp"],
      "env": {
        "TSHARK_PATH": "/absolute/path/to/tshark"
      }
    }
  }
}
```

…can use it. Absolute paths avoid “command not found” issues.

Use `python -m wireshark_mcp setup` to generate the block for your machine.

## Cursor

Project file: `.cursor/mcp.json`  
User file: `~/.cursor/mcp.json` (or `%USERPROFILE%\.cursor\mcp.json`)

After editing, reload the window or toggle the server in **Settings → MCP**.

Optional Cursor Agent Skill ships at [`.cursor/skills/wireshark-mcp/SKILL.md`](../.cursor/skills/wireshark-mcp/SKILL.md). Other hosts can ignore it.

## Claude Desktop

| OS | Config file |
|----|-------------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Prefer **Settings → Developer → Edit Config** inside the app so you open the file Claude actually reads. Fully quit and reopen the app after saving.

```bash
python -m wireshark_mcp setup --client claude-desktop
```

## Claude Code

| Scope | File |
|-------|------|
| User | `~/.claude.json` |
| Project | `.mcp.json` in the project root |

Same `mcpServers` schema as Claude Desktop.

```bash
python -m wireshark_mcp setup --client claude-code-user
# or
python -m wireshark_mcp setup --client claude-code-project
```

## VS Code / GitHub Copilot

Often `.vscode/mcp.json`. Some builds nest servers under an `servers` key — if your VS Code docs differ, paste only the inner `command` / `args` / `env` values into the shape your build expects.

```bash
python -m wireshark_mcp setup --client vscode
```

## Windsurf / other forks

Most accept the same Claude/Cursor-style `mcpServers` JSON. Use:

```bash
python -m wireshark_mcp setup --client print
```

and paste into that product’s MCP settings.

## Generic / custom agents

Any framework that can spawn:

```bash
/path/to/python -m wireshark_mcp
```

with env `TSHARK_PATH=...` over stdio is enough. No Cursor-specific APIs are required for tools to work.

## Naming

The setup CLI writes the server key as `wireshark`. You may rename the key (`wireshark-pyshark`, etc.); only the object body matters to the protocol.
