# Safe capture rules

Rules for using Wireshark MCP without leaking secrets or breaking hosts.

## Always

- Capture only traffic you are **authorized** to inspect.
- Prefer short captures (`duration` 3–10s) and tight display filters.
- Treat pcaps and verbose dumps as sensitive; redact secrets before sharing.
- If a tool returns `Error: ...`, report the failure — never invent packets.

## How this server hardens calls

- Interface names are allowlisted against `tshark -D` and rejected if they contain shell metacharacters.
- All TShark invocations use argv lists with `shell=False` (no shell interpolation).
- Failed captures return **errors**, never fabricated / simulated packets.
- Startup preflight exits if TShark is missing so hosts show the server offline instead of broken tools.

## Practical tips

| Situation | Do this |
|-----------|---------|
| Debugging your app | Capture only that interface + a host/port filter |
| Sharing with a teammate | Export a filtered pcap; strip cookies/tokens from HTTP views |
| Windows live capture | Install [Npcap](https://npcap.com/#download); confirm with `check_environment` |
| Offline only | Use `read_pcap_file` / HTTP+DNS file tools — no Npcap needed |

Next: [Troubleshooting](Troubleshooting.md) if the server stays offline, or [Start here](README.md) to finish setup.
