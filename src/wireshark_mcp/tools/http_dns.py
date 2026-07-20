"""HTTP/DNS analysis MCP tools (TShark-only)."""

from __future__ import annotations

import csv
import datetime
import io
import os
import tempfile
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context

from wireshark_mcp.formatting import format_http_analysis
from wireshark_mcp.security import (
    invalid_interface_message,
    validate_capture_interface,
    validate_pcap_read_path,
    validate_positive_int,
)
from wireshark_mcp.tshark_runner import (
    capture_to_temp_pcap,
    popen_tshark_capture,
    read_pcap_fields,
)

# popen_tshark_capture used by analyze_http_traffic_tabular


def register(mcp) -> None:
    @mcp.tool(name="analyze_http_traffic_tabular")
    def analyze_http_traffic_tabular(
        interface: str,
        duration: int = 30,
        include_https: bool = True,
    ) -> str:
        """Perform HTTP/HTTPS traffic analysis with tabular output."""
        safe_interface = validate_capture_interface(interface)
        if not safe_interface:
            return invalid_interface_message()
        duration = validate_positive_int(duration, default=30, minimum=1, maximum=300)

        timestamp = datetime.datetime.now().isoformat()
        capture_id = f"http_{timestamp.replace(':', '-')}"
        print(f"Starting HTTP traffic analysis on {safe_interface} for {duration}s...")

        display_filter = "http"
        if include_https:
            display_filter = "(http) or (tls)"

        fields = [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "http.request.method",
            "http.response.code",
            "http.request.uri",
            "http.host",
            "http.user_agent",
            "http.content_type",
            "http.content_length",
            "tls.handshake.type",
            "tls.handshake.extensions_server_name",
            "_ws.col.Protocol",
        ]
        args: List[str] = [
            "-i",
            safe_interface,
            "-f",
            "tcp port 80 or tcp port 443",
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
        ]
        for field in fields:
            args.extend(["-e", field])
        args.extend(["-a", f"duration:{duration}"])

        try:
            result = popen_tshark_capture(args, wait_seconds=duration + 5)
        except Exception as exc:
            return f"Error analyzing HTTP traffic: {exc}"

        http_packets: List[Dict[str, Any]] = []
        https_packets: List[Dict[str, Any]] = []
        reader = csv.reader(io.StringIO(result.stdout))
        for row in reader:
            if len(row) < 16:
                continue
            proto = (row[15] or "").upper()
            packet = {
                "num": row[0],
                "time": row[1] or "0",
                "src_ip": row[2],
                "dst_ip": row[3],
                "src_port": row[4],
                "dst_port": row[5],
                "method": row[6],
                "response_code": row[7],
                "uri": row[8],
                "host": row[9],
                "user_agent": row[10],
                "content_type": row[11],
                "content_length": row[12],
                "tls_handshake_type": row[13],
                "tls_sni": row[14],
                "protocol": row[15],
            }
            if "HTTP" in proto and "TLS" not in proto and "SSL" not in proto:
                http_packets.append(packet)
            else:
                https_packets.append(packet)

        if not http_packets and not https_packets:
            err = result.stderr.strip()
            detail = f" ({err})" if err else ""
            return f"Error: no HTTP/HTTPS packets captured{detail}"

        return format_http_analysis(
            capture_id,
            safe_interface,
            duration,
            http_packets,
            https_packets,
            include_https,
        )

    @mcp.tool(name="analyze_dns_traffic")
    def analyze_dns_traffic(
        interface: str = None,
        pcap_file: str = None,
        duration: int = 10,
        packet_count: Optional[int] = None,
        ctx: Context = None,
    ) -> str:
        """Analyze DNS traffic from a capture file or live capture."""
        if not pcap_file and not interface:
            return "Either pcap_file or interface must be provided"

        temp_pcap = None
        try:
            if pcap_file:
                path, path_err = validate_pcap_read_path(pcap_file)
                if path_err:
                    return path_err
                source = path
            else:
                safe = validate_capture_interface(interface)
                if not safe:
                    return invalid_interface_message()
                duration = validate_positive_int(
                    duration, default=10, minimum=1, maximum=300
                )
                if packet_count is not None:
                    packet_count = validate_positive_int(
                        packet_count, default=100, minimum=1, maximum=10000
                    )
                temp_pcap = os.path.join(
                    tempfile.gettempdir(),
                    f"dns_{int(datetime.datetime.now().timestamp())}.pcap",
                )
                # Capture general traffic, then filter DNS — avoids empty pcaps
                # when the window has traffic but no DNS (still a valid result).
                limit = packet_count if packet_count is not None else 200
                cap = capture_to_temp_pcap(
                    safe,
                    temp_pcap,
                    duration=duration,
                    packet_count=limit,
                )
                if not os.path.isfile(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                    return (
                        "Error analyzing DNS traffic: "
                        f"{cap.stderr.strip() or 'no packets captured'}"
                    )
                source = temp_pcap

            result = read_pcap_fields(
                source,
                [
                    "dns.flags.response",
                    "dns.qry.type",
                    "dns.qry.name",
                ],
                display_filter="dns",
                timeout=60,
            )

            query_types: Dict[str, int] = {}
            names: Dict[str, int] = {}
            queries = 0
            responses = 0
            total = 0
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                total += 1
                parts = line.split("\t")
                while len(parts) < 3:
                    parts.append("")
                flags_resp, qtype, qname = parts[:3]
                if flags_resp in ("1", "True", "true"):
                    responses += 1
                else:
                    queries += 1
                if qtype:
                    query_types[qtype] = query_types.get(qtype, 0) + 1
                if qname:
                    names[qname] = names.get(qname, 0) + 1

            if total == 0:
                return (
                    "DNS Traffic Analysis\n"
                    "===================\n"
                    "Total DNS Packets: 0\n"
                    "No DNS packets found in the capture window/file."
                )

            lines = [
                "DNS Traffic Analysis",
                "===================",
                f"Total DNS Packets: {total}",
                f"Queries: {queries}",
                f"Responses: {responses}",
            ]
            if query_types:
                lines.append("\nQuery Types:")
                for qtype, count in sorted(
                    query_types.items(), key=lambda x: x[1], reverse=True
                ):
                    lines.append(f"  - Type {qtype}: {count}")
            if names:
                lines.append("\nTop Names:")
                for name, count in sorted(
                    names.items(), key=lambda x: x[1], reverse=True
                )[:10]:
                    lines.append(f"  - {name}: {count}")
            return "\n".join(lines)
        except Exception as exc:
            return f"Error analyzing DNS traffic: {exc}"
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass
