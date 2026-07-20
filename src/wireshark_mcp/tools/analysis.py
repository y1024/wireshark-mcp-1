"""Traffic analysis MCP tools (TShark-only)."""

from __future__ import annotations

import csv
import datetime
import io
import os
import tempfile
from collections import Counter
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context

from wireshark_mcp.formatting import format_analysis_report, format_deep_analysis
from wireshark_mcp.security import (
    invalid_interface_message,
    validate_capture_interface,
    validate_display_filter,
    validate_pcap_read_path,
    validate_positive_int,
)
from wireshark_mcp.tshark_runner import (
    capture_to_temp_pcap,
    extract_stats_section,
    popen_tshark_capture,
    read_pcap_fields,
    run_tshark,
)


def register(mcp) -> None:
    @mcp.tool(name="analyze_traffic")
    def analyze_traffic(
        capture_index: int = -1,
        ctx: Context = None,
    ) -> str:
        """Analyze network traffic patterns from a previous capture in history."""
        if not ctx or not ctx.request_context or not ctx.request_context.lifespan_context:
            return "Error: Context required for this operation"
        history = ctx.request_context.lifespan_context.capture_history
        if not history:
            return "No capture history available"
        idx = capture_index if capture_index >= 0 else len(history) + capture_index
        if idx < 0 or idx >= len(history):
            return f"Invalid capture index: {capture_index}"
        capture = history[idx]
        lines = [
            f"Traffic Analysis for Capture: {capture.get('capture_id', 'Unknown')}",
            f"Timestamp: {capture.get('timestamp', 'Unknown')}",
            f"Total Packets: {capture.get('packet_count', 0)}",
            "\nProtocol Analysis:",
        ]
        summary = capture.get("protocol_summary") or {}
        total = max(capture.get("packet_count", 0), 1)
        for protocol, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            lines.append(
                f"  - {protocol}: {count} packets ({(count / total) * 100:.1f}%)"
            )
        return "\n".join(lines)

    @mcp.tool(name="analyze_http_traffic")
    def analyze_http_traffic(capture_file: str, format_type: str = "text") -> str:
        """Analyze HTTP traffic from a capture file."""
        path, path_err = validate_pcap_read_path(capture_file)
        if path_err:
            return path_err

        fields = [
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.response.code",
            "http.user_agent",
        ]
        try:
            result = read_pcap_fields(
                path, fields, display_filter="http", timeout=120
            )
        except Exception as exc:
            return f"Error analyzing HTTP traffic: {exc}"

        hosts: Counter = Counter()
        methods: Counter = Counter()
        status_codes: Counter = Counter()
        requests = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            while len(parts) < 5:
                parts.append("")
            method, host, uri, code, ua = parts[:5]
            if method:
                methods[method] += 1
            if host:
                hosts[host] += 1
            if code:
                status_codes[code] += 1
            if method or host or uri:
                requests.append(
                    {
                        "method": method or "unknown",
                        "host": host or "unknown",
                        "uri": uri or "/",
                        "user_agent": ua or "unknown",
                    }
                )

        analysis = {
            "timestamp": datetime.datetime.now().isoformat(),
            "capture_file": path,
            "http_requests_count": len(requests),
            "hosts": dict(hosts),
            "methods": dict(methods),
            "status_codes": dict(status_codes),
            "requests": requests[:100],
            "packet_count": len(requests),
        }
        text, _mime = format_analysis_report(analysis, format_type)
        return text

    @mcp.tool(name="detect_protocols")
    def detect_protocols(
        interface: str = None,
        capture_file: str = None,
        duration: int = 30,
        format_type: str = "text",
    ) -> str:
        """Detect and report network protocols in use."""
        if not capture_file and not interface:
            return "Error: Either capture_file or interface must be provided"

        temp_pcap = None
        try:
            if capture_file:
                path, path_err = validate_pcap_read_path(capture_file)
                if path_err:
                    return path_err
                source = path
                source_label = path
            else:
                safe = validate_capture_interface(interface)
                if not safe:
                    return invalid_interface_message()
                duration = validate_positive_int(
                    duration, default=30, minimum=1, maximum=300
                )
                temp_pcap = os.path.join(
                    tempfile.gettempdir(),
                    f"detect_{int(datetime.datetime.now().timestamp())}.pcap",
                )
                cap = capture_to_temp_pcap(safe, temp_pcap, duration=duration)
                if not os.path.isfile(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                    return f"Error detecting protocols: {cap.stderr.strip() or 'empty capture'}"
                source = temp_pcap
                source_label = f"live capture on {safe}"

            result = read_pcap_fields(
                source, ["_ws.col.Protocol", "frame.protocols"], timeout=120
            )
            app_protocols: Counter = Counter()
            layer_counts: Counter = Counter()
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                proto = parts[0].strip() if parts else ""
                stack = parts[1].strip() if len(parts) > 1 else ""
                if proto:
                    app_protocols[proto] += 1
                if stack:
                    for layer in stack.split(":"):
                        if layer:
                            layer_counts[layer] += 1

            packet_count = sum(app_protocols.values())
            insights = []
            keys = {k.lower() for k in app_protocols}
            if "http" in keys:
                insights.append("Web traffic (HTTP) detected")
            if any(k.startswith("tls") or k == "ssl" for k in keys):
                insights.append("Encrypted web traffic (HTTPS/TLS) detected")
            if "dns" in keys:
                insights.append("DNS queries detected")

            results = {
                "timestamp": datetime.datetime.now().isoformat(),
                "source": source_label,
                "packet_count": packet_count,
                "layer_protocols": dict(layer_counts),
                "application_protocols": dict(app_protocols),
                "insights": insights,
            }
            text, _mime = format_analysis_report(results, format_type)
            return text
        except Exception as exc:
            return f"Error detecting protocols: {exc}"
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass

    @mcp.tool(name="deep_packet_analysis")
    def deep_packet_analysis(
        interface: str,
        duration: int = 10,
        packets: int = 100,
        include_details: bool = True,
        max_packet_display: int = 100,
        ctx: Context = None,
    ) -> str:
        """Perform a deep packet analysis with detailed tabular output."""
        safe_interface = validate_capture_interface(interface)
        if not safe_interface:
            return invalid_interface_message()
        duration = validate_positive_int(duration, default=10, minimum=1, maximum=300)
        packets = validate_positive_int(packets, default=100, minimum=1, maximum=100000)

        timestamp = datetime.datetime.now().isoformat()
        capture_id = f"deep_{timestamp.replace(':', '-')}"
        fields = [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "_ws.col.Protocol",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "ip.len",
            "_ws.col.Info",
            "frame.len",
        ]
        args: List[str] = [
            "-i",
            safe_interface,
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
        ]
        for field in fields:
            args.extend(["-e", field])
        args.extend(["-a", f"duration:{duration}", "-c", str(packets)])

        try:
            result = popen_tshark_capture(args, wait_seconds=duration + 5)
        except Exception as exc:
            return f"Error in deep packet analysis: {exc}"

        packets_data: List[Dict[str, Any]] = []
        reader = csv.reader(io.StringIO(result.stdout))
        for row in reader:
            if len(row) < 12:
                continue
            src_port = row[5] or row[7]
            dst_port = row[6] or row[8]
            packets_data.append(
                {
                    "num": row[0],
                    "time": row[1] or "0",
                    "src_ip": row[2],
                    "dst_ip": row[3],
                    "protocol": row[4],
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": row[11] or row[9] or "0",
                    "info": row[10],
                }
            )

        if not packets_data:
            err = result.stderr.strip()
            detail = f" ({err})" if err else ""
            return f"Error: no packet data captured for deep analysis{detail}"

        return format_deep_analysis(
            capture_id,
            safe_interface,
            duration,
            packets_data,
            include_details,
            max_packet_display,
        )

    @mcp.tool(name="protocol_hierarchy_statistics")
    def protocol_hierarchy_statistics(
        interface: str = None,
        pcap_file: str = None,
        duration: int = 10,
        packet_count: Optional[int] = None,
        ctx: Context = None,
    ) -> str:
        """Show protocol hierarchy statistics for captured traffic."""
        if not interface and not pcap_file:
            return "Error: Either interface or pcap_file must be specified"

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
                temp_pcap = os.path.join(
                    tempfile.gettempdir(),
                    f"phs_capture_{int(datetime.datetime.now().timestamp())}.pcap",
                )
                cap_result = capture_to_temp_pcap(
                    safe,
                    temp_pcap,
                    duration=duration,
                    packet_count=packet_count,
                )
                if not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                    err = cap_result.stderr.strip()
                    return f"Error capturing packets for protocol hierarchy: {err or 'empty capture'}"
                source = temp_pcap

            # -q suppresses packet list; stats go to stdout/stderr
            result = run_tshark(["-r", source, "-q", "-z", "io,phs"], timeout=60)
            body = extract_stats_section(
                (result.stdout or "") + "\n" + (result.stderr or ""),
                "Protocol Hierarchy Statistics",
            )
            if not body:
                return f"Error computing protocol hierarchy: {result.stderr.strip()}"
            return "PROTOCOL HIERARCHY STATISTICS\n=============================\n\n" + body
        except Exception as exc:
            return f"Error in protocol hierarchy statistics: {exc}"
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass
