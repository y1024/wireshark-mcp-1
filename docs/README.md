# Wireshark MCP wiki

Novice-friendly guides for running this server with **any** stdio MCP host.

| Page | What it covers |
|------|----------------|
| [Setup](Setup.md) | Install Python, TShark, Npcap, and this package |
| [Clients](Clients.md) | Cursor, Claude Desktop, Claude Code, VS Code, Windsurf, generic |
| [Troubleshooting](Troubleshooting.md) | Offline/red server, missing tshark, live capture |
| [Security](Security.md) | Safe capture rules and hardening notes |

Quick start from the repo root:

```bash
python -m pip install -e .
python -m wireshark_mcp doctor
python -m wireshark_mcp setup
```

Then paste or write the printed config into your MCP host and reload it.
