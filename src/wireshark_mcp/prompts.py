"""MCP prompts — guided workflows for packet capture and analysis."""

from __future__ import annotations


def register_prompts(mcp) -> None:
    @mcp.prompt()
    def packet_capture_help() -> str:
        """Overview of Wireshark MCP capture and analysis workflows."""
        return """
You are helping with packet capture via the wireshark-pyshark MCP server.

Workflow:
1. Call list_interfaces and use an exact returned name (e.g. "Wi-Fi").
2. Prefer short captures first: quick_capture(interface, duration=3, packet_limit=20).
3. Dig deeper with protocol_hierarchy_statistics, analyze_dns_traffic, or analyze_http_traffic_tabular.
4. For offline files use read_pcap_file and analyze_http_traffic / filtered_packet_display.
5. Never invent or simulate traffic. If a tool returns an Error, report it honestly.
6. Only capture traffic you are authorized to inspect.
"""

    @mcp.prompt()
    def investigate_live_traffic() -> str:
        """Step-by-step live traffic investigation."""
        return """
Investigate live network traffic using wireshark-pyshark tools:

1. list_interfaces — pick a local NIC (prefer Wi-Fi/Ethernet; avoid *dump remote extcap).
2. quick_capture(interface, duration=5, packet_limit=50) — baseline talkers/protocols.
3. protocol_hierarchy_statistics(interface=..., duration=5) — stack breakdown.
4. analyze_dns_traffic(interface=..., duration=5) — name resolution activity.
5. analyze_http_traffic_tabular(interface=..., duration=5, include_https=True) — web/TLS.
6. Summarize findings; if a step errors, stop inventing data and explain the failure.
"""

    @mcp.prompt()
    def analyze_pcap_file() -> str:
        """Offline pcap/pcapng analysis workflow."""
        return """
Analyze an existing capture file:

1. Confirm the path exists, then read_pcap_file(file_path=...).
2. protocol_hierarchy_statistics(pcap_file=...).
3. analyze_http_traffic(capture_file=...) for cleartext HTTP.
4. analyze_dns_traffic(pcap_file=...).
5. filtered_packet_display(display_filter=..., pcap_file=...) for focused views
   (examples: "tcp.port == 443", "dns", "http").
6. expert_information(pcap_file=...) for Wireshark expert warnings.
Do not fabricate packet contents if tools return errors or empty results.
"""

    @mcp.prompt()
    def security_traffic_review() -> str:
        """Security-oriented review of captures."""
        return """
Security traffic review checklist:

1. Capture or open only authorized traffic.
2. expert_information — note warnings/errors/chatty protocols.
3. deep_packet_analysis or protocol_hierarchy_statistics — look for cleartext
   (HTTP, FTP, Telnet) and unexpected high ports.
4. analyze_http_traffic_tabular — flag sensitive URIs over plain HTTP.
5. analyze_dns_traffic — unusual query volume or unexpected domains.
6. Redact secrets (cookies, tokens, Authorization headers) before sharing output.
7. Never claim findings from simulated/fake data — this server returns errors instead.
"""

    @mcp.prompt()
    def safe_capture_rules() -> str:
        """Authorization, least privilege, and integrity rules for capture work."""
        return """
Safe capture rules (always follow):

- Authorization: only capture networks/systems you own or have explicit permission to monitor.
- Least privilege: prefer short duration and packet limits; avoid full-disk capture dumps.
- Integrity: never invent packets; surface tool Errors as-is.
- Interface safety: only pass exact names from list_interfaces (prevents command injection).
- Privacy: treat pcaps as sensitive; store under the configured captures directory.
- Platform: live capture needs TShark + Npcap/libpcap and often elevated privileges.
"""
