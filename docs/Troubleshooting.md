# Troubleshooting

## Server stays offline / red / error

1. Run the same command your host uses:

   ```bash
   # activate your venv first
   python -m wireshark_mcp doctor
   ```

2. If doctor fails, install Wireshark/TShark or set `TSHARK_PATH`.
3. Run `python -m wireshark_mcp setup` and reload the host.
4. Confirm `command` is an **absolute** path to the venv Python that has this package installed.

This server **exits on startup** when TShark is missing. That is intentional: hosts treat a failed process as offline instead of advertising broken tools.

## `tshark not found`

- Install Wireshark so `tshark` exists.
- Or set in MCP config:

  ```json
  "env": {
    "TSHARK_PATH": "C:\\Program Files\\Wireshark\\tshark.exe"
  }
  ```

- On PATH-only installs, ensure the host process inherits PATH (GUI apps on macOS/Windows often do not). Prefer `TSHARK_PATH`.

## Live capture fails, file analysis works

- Windows: install [Npcap](https://npcap.com/#download) and reboot if prompted.
- Use `list_interfaces` and pass an **exact** interface name.
- Capture only on networks you are authorized to inspect.
- Prefer short durations (3–10 seconds).

## Tools error with event-loop / PyShark messages

Current tools drive **TShark directly**. Reload the MCP server after upgrading so the host is not running an old process.

## Wrong Python / module not found

```bash
/absolute/path/to/.venv/Scripts/python.exe -m wireshark_mcp doctor   # Windows
/absolute/path/to/.venv/bin/python -m wireshark_mcp doctor           # Unix
```

Reinstall into that interpreter:

```bash
python -m pip install -e .
```

## Permission denied capturing

Unix: add your user to the `wireshark` group (distro-specific) or run with appropriate capabilities. Prefer analyzing saved pcaps when possible.
