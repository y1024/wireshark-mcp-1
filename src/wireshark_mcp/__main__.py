"""python -m wireshark_mcp [run|setup|doctor]"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "run"

    if cmd in ("-h", "--help", "help"):
        print(
            "Usage:\n"
            "  python -m wireshark_mcp              # run MCP server (preflight required)\n"
            "  python -m wireshark_mcp run          # same\n"
            "  python -m wireshark_mcp setup        # prompt for TShark + write/print config\n"
            "  python -m wireshark_mcp setup --client print|cursor|claude-desktop|...\n"
            "  python -m wireshark_mcp doctor       # print dependency status (exit 0/1)\n"
        )
        raise SystemExit(0)

    if cmd == "setup":
        from wireshark_mcp.preflight import interactive_setup

        client_id = None
        if "--client" in argv:
            i = argv.index("--client")
            if i + 1 < len(argv):
                client_id = argv[i + 1]
        raise SystemExit(interactive_setup(client_id=client_id))

    if cmd == "doctor":
        from wireshark_mcp.preflight import run_preflight

        report = run_preflight()
        print(report.to_json())
        raise SystemExit(0 if report.ok else 1)

    if cmd == "run":
        argv = argv[1:]

    from wireshark_mcp.preflight import ensure_ready_or_exit
    from wireshark_mcp.server import main as run_server

    ensure_ready_or_exit()
    run_server()


if __name__ == "__main__":
    main()
