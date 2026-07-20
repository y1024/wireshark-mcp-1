# Get Wireshark into your AI agent

**Wireshark MCP** lets Cursor, Claude, VS Code, and other MCP hosts capture and analyze packets with TShark.

You only need three things: **Python 3.10+**, **TShark**, and this package.

## Do this first (5 minutes)

```bash
git clone https://github.com/A-G-U-P-T-A/wireshark-mcp
cd wireshark-mcp
python -m venv .venv

# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

python -m pip install -e .
python -m wireshark_mcp doctor
python -m wireshark_mcp setup
```

`doctor` must exit **0**. `setup` prints or writes a `mcpServers` block with absolute paths.

Then reload MCP in your host and ask the agent to call `check_environment` or `list_interfaces`.

### Install TShark if doctor fails

| OS | Command |
|----|---------|
| Windows | `winget install --id WiresharkFoundation.Wireshark -e` (+ [Npcap](https://npcap.com/#download) for live capture) |
| macOS | `brew install wireshark` |
| Linux | `sudo apt-get install -y tshark` |

## Pick your host

| Host | Config location | Shortcut |
|------|-----------------|----------|
| [Cursor](clients.html#cursor) | `.cursor/mcp.json` | `setup --client cursor` |
| [Claude Desktop](clients.html#claude-desktop) | `claude_desktop_config.json` | `setup --client claude-desktop` |
| [Claude Code](clients.html#claude-code) | `~/.claude.json` or `.mcp.json` | `setup --client claude-code-user` |
| [VS Code / Copilot](clients.html#vs-code-github-copilot) | `.vscode/mcp.json` | `setup --client vscode` |
| Anything else | paste JSON from setup | `setup --client print` |

## Config shape (any host)

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

Windows example: `...\Scripts\python.exe` and `C:\Program Files\Wireshark\tshark.exe`.

## What you can do after it is online

| Goal | Tool |
|------|------|
| Confirm deps | `check_environment` |
| List NICs | `list_interfaces` |
| Short live sample | `quick_capture` |
| Read a pcap | `read_pcap_file` |
| DNS / HTTP | `analyze_dns_traffic`, `analyze_http_traffic_tabular` |

## Guides

- [Full setup](Setup.md) — step-by-step with Npcap and venv details  
- [MCP clients](Clients.md) — exact file paths per product  
- [Troubleshooting](Troubleshooting.md) — offline/red server, PATH, live capture  
- [Security](Security.md) — authorization and hardening  

Repo: [A-G-U-P-T-A/wireshark-mcp](https://github.com/A-G-U-P-T-A/wireshark-mcp) · Release: [v0.2.2](https://github.com/A-G-U-P-T-A/wireshark-mcp/releases/tag/v0.2.2)
