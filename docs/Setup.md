# Setup (novice guide)

You need three things:

1. **Python 3.10+**
2. **TShark** (ships with Wireshark)
3. This package installed so `python -m wireshark_mcp` works

Live capture on Windows also needs **Npcap**.

## 1. Install TShark / Wireshark

### Windows

```bash
winget install --id WiresharkFoundation.Wireshark -e
```

For live capture, install [Npcap](https://npcap.com/#download) as well.

Default binary path:

`C:\Program Files\Wireshark\tshark.exe`

### macOS

```bash
brew install wireshark
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y tshark
```

You may need to add your user to the `wireshark` group for live capture.

## 2. Install this MCP server

```bash
git clone https://github.com/A-G-U-P-T-A/wireshark-mcp
cd wireshark-mcp
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e .
```

Optional (tests / contributors):

```bash
python -m pip install -e ".[dev]"
```

## 3. Check dependencies

```bash
python -m wireshark_mcp doctor
```

Exit code `0` means TShark was found. Exit code `1` means install or set `TSHARK_PATH`.

## 4. Configure your MCP host

```bash
python -m wireshark_mcp setup
```

The wizard:

1. Detects or asks for the `tshark` path
2. Lets you pick a host (Cursor, Claude Desktop, Claude Code, print-only, …)
3. Writes `command` / `args` / `env.TSHARK_PATH` in the common `mcpServers` JSON shape

Non-interactive print:

```bash
python -m wireshark_mcp setup --client print
```

Template (edit the placeholders): [`examples/mcpServers.wireshark.json`](../examples/mcpServers.wireshark.json)

## 5. Reload the host

Fully restart or reload MCP in your client. The server should come **online** only when TShark is available — otherwise it exits on purpose so the host shows an error instead of a broken tool list.

## 6. Smoke test

In the agent chat (after the server is online):

- Call `check_environment`
- Call `list_interfaces`

Or from a terminal:

```bash
pytest -q -m "not live"
```

Next: [Clients.md](Clients.md)
