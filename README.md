# Wireshark MCP Server

Packet capture and analysis for AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP).

Works with **any stdio MCP host**: Cursor, Claude Desktop, Claude Code, VS Code / Copilot, Windsurf, custom agents, and similar tools. No vendor lock-in — the host only needs to launch:

```text
python -m wireshark_mcp
```

**Version 0.2.2**

| Docs (wiki) | |
|-------------|--|
| [Setup for novices](docs/Setup.md) | Install TShark + this package |
| [MCP clients](docs/Clients.md) | Cursor, Claude, VS Code, generic |
| [Troubleshooting](docs/Troubleshooting.md) | Offline server, PATH issues |
| [Security](docs/Security.md) | Safe capture rules |

## What you get

- Live capture and pcap/pcapng analysis through MCP **tools**
- Guided workflows via MCP **prompts**
- Startup **preflight**: if TShark is missing, the process exits so your host shows the server offline/error instead of a broken tool list
- `setup` / `doctor` CLIs so a new user can configure paths without guessing

## Requirements

- Python **3.10+**
- [TShark](https://www.wireshark.org/download.html) (`PATH` or `TSHARK_PATH`)
- [Npcap](https://npcap.com/#download) (Windows) or libpcap (Unix) for **live** capture
- Authorization to capture on the target network

## Quick start (5 minutes)

```bash
git clone https://github.com/A-G-U-P-T-A/wireshark-mcp
cd wireshark-mcp
python -m venv .venv

# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate

python -m pip install -e .
python -m wireshark_mcp doctor
python -m wireshark_mcp setup
```

`setup` detects TShark (or asks for its path) and writes or prints a standard `mcpServers` JSON block. Point your host at that config, then **reload / restart** the host.

Windows Wireshark install:

```bash
winget install --id WiresharkFoundation.Wireshark -e
```

## MCP config (any host)

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "wireshark_mcp"],
      "env": {
        "TSHARK_PATH": "/absolute/path/to/tshark"
      }
    }
  }
}
```

Windows example paths:

- Python: `C:\\Users\\YOU\\...\\wireshark-mcp\\.venv\\Scripts\\python.exe`
- TShark: `C:\\Program Files\\Wireshark\\tshark.exe`

Ready-made template: [`examples/mcpServers.wireshark.json`](examples/mcpServers.wireshark.json)  
Client-specific file locations: [`docs/Clients.md`](docs/Clients.md)

### CLI

| Command | Purpose |
|---------|---------|
| `python -m wireshark_mcp` | Run the MCP server (stdio) |
| `python -m wireshark_mcp doctor` | JSON dependency report (exit 0/1) |
| `python -m wireshark_mcp setup` | Interactive TShark + host config |
| `python -m wireshark_mcp setup --client print` | Print JSON only |

## Project layout

```text
src/wireshark_mcp/     # MCP server package (tools, prompts, preflight)
examples/              # Sample mcpServers JSON
docs/                  # Setup wiki for novices
tests/                 # pytest (no live capture by default)
.cursor/skills/        # Optional Cursor agent skill
pyshark_mcp.py         # Thin legacy shim
```

## Tools (selected)

| Area | Tools |
|------|--------|
| Setup | `check_environment`, `configure_tshark` |
| Capture | `list_interfaces`, `quick_capture`, `capture_live_packets`, `save_capture_to_file` |
| Analysis | `read_pcap_file`, `analyze_traffic`, `deep_packet_analysis`, `quick_traffic_analysis` |
| App protocols | `analyze_dns_traffic`, `analyze_http_traffic`, `analyze_http_traffic_tabular` |
| Diagnostics | `protocol_hierarchy_statistics`, `expert_information`, `filtered_packet_display` |

## Prompts & resources

**Prompts:** `packet_capture_help`, `investigate_live_traffic`, `analyze_pcap_file`, `security_traffic_review`, `safe_capture_rules`

**Resources:** `pyshark://version`, `pyshark://config` (`allow_simulation` is always `false`)

## Security

- Interfaces allowlisted from `tshark -D`; shell metacharacters rejected
- Subprocesses use argv + `shell=False`
- Failures return errors — **no simulated packets**

Details: [docs/Security.md](docs/Security.md)

## Tests & CI

```bash
python -m pip install -e ".[dev]"
pytest -q -m "not live"
```

GitHub Actions installs TShark on Ubuntu and runs the non-live suite.

## License

MIT
