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

## GitHub Pages

The `Pages` workflow publishes this wiki as HTML.

1. Repo **Settings → Pages → Build and deployment → Source: GitHub Actions**
2. Push to `main`/`master`, or run the **Pages** workflow manually
3. Site URL: `https://<owner>.github.io/wireshark-mcp/`

If `configure-pages` fails with **Get Pages site failed / Not Found**, step 1 was skipped (or org policy blocked auto-enable). Set Source to GitHub Actions once, then re-run the workflow.

The Node 20 deprecation line in the log is a runner warning from the Pages actions — not the cause of the failure.
