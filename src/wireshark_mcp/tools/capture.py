"""Capture-related MCP tools (TShark-only; no PyShark event loop)."""

from __future__ import annotations

import datetime
import json
import os
import time
from typing import List, Optional

from mcp.server.fastmcp import Context

from wireshark_mcp.formatting import format_capture_summary, format_quick_capture
from wireshark_mcp.interfaces import list_interfaces as enumerate_interfaces
from wireshark_mcp.security import (
    invalid_interface_message,
    validate_bpf_filter,
    validate_capture_interface,
    validate_pcap_read_path,
    validate_pcap_write_path,
    validate_positive_int,
    validate_target_host,
)
from wireshark_mcp.tshark_runner import (
    capture_to_pcap,
    popen_tshark_capture,
    read_pcap_fields,
)


def list_interfaces() -> List[str]:
    """Get list of available network interfaces using TShark."""
    return enumerate_interfaces()


def _append_history(ctx: Context, summary: dict) -> None:
    if ctx and ctx.request_context and ctx.request_context.lifespan_context:
        ctx.request_context.lifespan_context.capture_history.append(summary)


def quick_capture(
    interface: str,
    duration: int = 3,
    packet_limit: int = 10,
) -> str:
    """Perform a quick packet capture and return results directly."""
    safe_interface = validate_capture_interface(interface)
    if not safe_interface:
        return invalid_interface_message()

    duration = validate_positive_int(duration, default=3, minimum=1, maximum=120)
    packet_limit = validate_positive_int(
        packet_limit, default=10, minimum=1, maximum=10000
    )

    print(
        f"Starting quick capture on {safe_interface} "
        f"for {duration}s or {packet_limit} packets..."
    )
    timestamp = datetime.datetime.now().isoformat()
    capture_id = f"quick_{timestamp.replace(':', '-')}"

    try:
        result = popen_tshark_capture(
            [
                "-i",
                safe_interface,
                "-c",
                str(packet_limit),
                "-a",
                f"duration:{duration}",
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "_ws.col.Protocol",
            ],
            wait_seconds=duration + 2,
        )
    except Exception as exc:
        return f"Error in quick capture: {exc}"

    packets = []
    protocols: dict[str, int] = {}
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.strip().split("\t")
        if len(parts) >= 4:
            _num, src, dst, proto = parts
            packets.append({"src": src, "dst": dst, "proto": proto})
            protocols[proto] = protocols.get(proto, 0) + 1

    if not packets:
        err = result.stderr.strip()
        detail = f" ({err})" if err else ""
        return f"Error: no packets captured on {safe_interface}{detail}"

    return format_quick_capture(
        capture_id, safe_interface, len(packets), protocols, packets
    )


def register(mcp) -> None:
    @mcp.tool(name="list_interfaces")
    def _list_interfaces() -> List[str]:
        """Get list of available network interfaces using TShark."""
        return list_interfaces()

    @mcp.tool(name="get_capture_history")
    def get_capture_history(ctx: Context = None) -> str:
        """Get history of previous packet captures."""
        if ctx and ctx.request_context and ctx.request_context.lifespan_context:
            history = ctx.request_context.lifespan_context.capture_history
            return json.dumps(history, indent=2)
        return json.dumps([], indent=2)

    @mcp.tool(name="quick_capture")
    def _quick_capture(
        interface: str,
        duration: int = 3,
        packet_limit: int = 10,
    ) -> str:
        """Perform a quick packet capture and return results directly."""
        return quick_capture(interface, duration, packet_limit)

    @mcp.tool(name="capture_live_packets")
    def capture_live_packets(
        interface: str,
        capture_filter: str = "",
        duration: int = 10,
        packet_count: Optional[int] = None,
        ctx: Context = None,
    ) -> str:
        """Capture live packets from a network interface."""
        safe_interface = validate_capture_interface(interface)
        if not safe_interface:
            return invalid_interface_message()
        bpf, bpf_err = validate_bpf_filter(capture_filter)
        if bpf_err:
            return bpf_err
        duration = validate_positive_int(duration, default=10, minimum=1, maximum=300)
        if packet_count is not None:
            packet_count = validate_positive_int(
                packet_count, default=100, minimum=1, maximum=100000
            )

        args = [
            "-i",
            safe_interface,
            "-a",
            f"duration:{duration}",
            "-T",
            "fields",
            "-e",
            "_ws.col.Protocol",
        ]
        if packet_count is not None:
            args.extend(["-c", str(packet_count)])
        if bpf:
            args.extend(["-f", bpf])

        try:
            result = popen_tshark_capture(args, wait_seconds=duration + 5)
        except Exception as exc:
            return f"Error capturing packets: {exc}"

        protocol_counts: dict[str, int] = {}
        for line in result.stdout.strip().split("\n"):
            proto = line.strip()
            if proto:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        packet_total = sum(protocol_counts.values())
        if packet_total == 0:
            err = result.stderr.strip()
            return f"Error: no packets captured ({err})" if err else "Error: no packets captured"

        timestamp = datetime.datetime.now().isoformat()
        summary = {
            "capture_id": f"live_{timestamp.replace(':', '-')}",
            "timestamp": timestamp,
            "interface": safe_interface,
            "filter": bpf or "",
            "duration": duration,
            "packet_count": packet_total,
            "protocol_summary": protocol_counts,
        }
        _append_history(ctx, summary)
        return format_capture_summary(summary)

    @mcp.tool(name="read_pcap_file")
    def read_pcap_file(
        file_path: str,
        display_filter: str = "",
        ctx: Context = None,
    ) -> str:
        """Read and analyze a packet capture file."""
        from wireshark_mcp.security import validate_display_filter

        path, path_err = validate_pcap_read_path(file_path)
        if path_err:
            return path_err
        disp, disp_err = validate_display_filter(display_filter)
        if disp_err:
            return disp_err

        try:
            result = read_pcap_fields(
                path,
                ["_ws.col.Protocol"],
                display_filter=disp or "",
                timeout=120,
            )
        except Exception as exc:
            return f"Error reading capture file: {exc}"

        protocol_counts: dict[str, int] = {}
        for line in result.stdout.strip().split("\n"):
            proto = line.strip()
            if proto:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        packet_total = sum(protocol_counts.values())

        timestamp = datetime.datetime.now().isoformat()
        file_name = os.path.basename(path)
        summary = {
            "capture_id": f"file_{file_name}_{timestamp.replace(':', '-')}",
            "timestamp": timestamp,
            "file_path": path,
            "filter": disp or "",
            "packet_count": packet_total,
            "protocol_summary": protocol_counts,
        }
        _append_history(ctx, summary)
        return format_capture_summary(summary)

    @mcp.tool(name="capture_targeted_traffic")
    def capture_targeted_traffic(
        interface: str,
        target_host: str = None,
        target_port: int = None,
        protocol: str = None,
        duration: int = 30,
        packet_limit: int = 1000,
        ctx: Context = None,
    ) -> str:
        """Capture traffic targeted to specific host, port, or protocol."""
        safe_interface = validate_capture_interface(interface)
        if not safe_interface:
            return invalid_interface_message()
        duration = validate_positive_int(duration, default=30, minimum=1, maximum=300)
        packet_limit = validate_positive_int(
            packet_limit, default=1000, minimum=1, maximum=100000
        )

        host, host_err = validate_target_host(target_host)
        if host_err:
            return host_err

        filter_parts: List[str] = []
        if host:
            filter_parts.append(f"host {host}")
        if target_port is not None:
            port = validate_positive_int(
                target_port, default=80, minimum=1, maximum=65535
            )
            filter_parts.append(f"port {port}")
        if protocol:
            proto = str(protocol).strip().lower()
            if proto in ("http",):
                filter_parts.append("tcp port 80")
            elif proto in ("https", "tls", "ssl"):
                filter_parts.append("tcp port 443")
            elif proto in ("tcp", "udp", "icmp"):
                filter_parts.append(proto)
            else:
                return "Error: unsupported protocol (use tcp/udp/icmp/http/https)"

        bpf = " and ".join(filter_parts)
        bpf_ok, bpf_err = validate_bpf_filter(bpf)
        if bpf_err:
            return bpf_err

        args = [
            "-i",
            safe_interface,
            "-c",
            str(packet_limit),
            "-a",
            f"duration:{duration}",
            "-T",
            "fields",
            "-e",
            "_ws.col.Protocol",
        ]
        if bpf_ok:
            args.extend(["-f", bpf_ok])

        start = time.time()
        try:
            result = popen_tshark_capture(args, wait_seconds=duration + 5)
        except Exception as exc:
            return f"Error in targeted capture: {exc}"
        elapsed = time.time() - start

        protocol_counts: dict[str, int] = {}
        for line in result.stdout.strip().split("\n"):
            proto = line.strip()
            if proto:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        packet_total = sum(protocol_counts.values())
        if packet_total == 0:
            err = result.stderr.strip()
            return f"Error: no targeted packets captured ({err})" if err else "Error: no targeted packets captured"

        timestamp = datetime.datetime.now().isoformat()
        summary = {
            "capture_id": f"targeted_{timestamp.replace(':', '-')}",
            "timestamp": timestamp,
            "interface": safe_interface,
            "filter": bpf_ok or "",
            "duration_seconds": elapsed,
            "packet_count": packet_total,
            "protocol_summary": protocol_counts,
        }
        _append_history(ctx, summary)

        lines = [
            f"Targeted Capture ID: {summary['capture_id']}",
            f"Interface: {safe_interface}",
            f"Filter: {bpf_ok or 'None'}",
            f"Duration: {elapsed:.2f} seconds",
            f"Packet Count: {packet_total}",
            "\nProtocol Distribution:",
        ]
        for proto, count in sorted(
            protocol_counts.items(), key=lambda x: x[1], reverse=True
        ):
            lines.append(
                f"  - {proto}: {count} packets ({(count / packet_total) * 100:.1f}%)"
            )
        return "\n".join(lines)

    @mcp.tool(name="save_capture_to_file")
    def save_capture_to_file(
        interface: str,
        output_file: str,
        capture_filter: str = "",
        duration: int = 60,
        packet_limit: Optional[int] = None,
        ctx: Context = None,
    ) -> str:
        """Capture network traffic and save to a pcap file."""
        safe_interface = validate_capture_interface(interface)
        if not safe_interface:
            return invalid_interface_message()
        duration = validate_positive_int(duration, default=60, minimum=1, maximum=3600)
        bpf, bpf_err = validate_bpf_filter(capture_filter)
        if bpf_err:
            return bpf_err

        captures_dir = "./captures"
        if ctx and ctx.request_context and ctx.request_context.lifespan_context:
            captures_dir = ctx.request_context.lifespan_context.config.get(
                "capture_dir", captures_dir
            )
        path, path_err = validate_pcap_write_path(
            output_file, captures_dir=captures_dir
        )
        if path_err:
            return path_err

        if packet_limit is not None:
            packet_limit = validate_positive_int(
                packet_limit, default=1000, minimum=1, maximum=100000
            )

        start = time.time()
        try:
            result = capture_to_pcap(
                safe_interface,
                path,
                duration=duration,
                packet_count=packet_limit,
                capture_filter=bpf or "",
            )
        except Exception as exc:
            return f"Error saving capture: {exc}"
        elapsed = time.time() - start

        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            err = result.stderr.strip()
            return f"Error saving capture: {err or 'empty capture file'}"

        timestamp = datetime.datetime.now().isoformat()
        summary = {
            "capture_id": f"file_{timestamp.replace(':', '-')}",
            "timestamp": timestamp,
            "interface": safe_interface,
            "output_file": path,
            "filter": bpf or "",
            "duration_seconds": elapsed,
            "status": "completed",
        }
        _append_history(ctx, summary)
        return (
            f"Capture saved to {path}\n"
            f"Capture ID: {summary['capture_id']}\n"
            f"Duration: {elapsed:.2f}s"
        )

    @mcp.tool(name="quick_traffic_analysis")
    def quick_traffic_analysis(
        interface: str,
        duration: int = 5,
        packets: int = 20,
    ) -> str:
        """Perform a quick capture and immediate analysis on an interface."""
        capture_output = quick_capture(interface, duration, packets)
        if capture_output.startswith("Error"):
            return capture_output

        lines = capture_output.split("\n")
        capture_id = (
            lines[0].replace("Quick Capture ID: ", "") if lines else "unknown"
        )
        analysis = [
            f"Traffic Analysis for {interface}",
            f"Capture ID: {capture_id}",
            f"Duration: {duration} seconds",
            f"Max Packets: {packets}",
            "\n=== ANALYSIS RESULTS ===",
        ]

        protocols_found: dict[str, int] = {}
        in_proto = False
        for line in lines:
            if line == "Protocol Distribution:":
                in_proto = True
                continue
            if in_proto and line.strip().startswith("-"):
                parts = line.strip().replace("  - ", "").split(":")
                if len(parts) >= 2:
                    proto = parts[0].strip()
                    count_parts = parts[1].strip().split()
                    if count_parts:
                        protocols_found[proto] = int(count_parts[0])
            elif in_proto and line.strip() == "":
                in_proto = False

        insights = []
        web = sum(
            protocols_found.get(p, 0)
            for p in ("HTTP", "HTTPS", "TLS", "TLSv1.2", "TLSv1.3", "SSL")
        )
        if web:
            insights.append(f"Web Traffic: Detected {web} web-related packets")
        dns = protocols_found.get("DNS", 0)
        if dns:
            insights.append(f"DNS Activity: Detected {dns} DNS packets")

        if protocols_found:
            analysis.append("\nProtocol Distribution:")
            for proto, count in sorted(
                protocols_found.items(), key=lambda x: x[1], reverse=True
            ):
                analysis.append(f"  - {proto}: {count}")
        if insights:
            analysis.append("\nInsights:")
            for insight in insights:
                analysis.append(f"  - {insight}")
        analysis.append("\nSecurity Observations:")
        if any(p in protocols_found for p in ("TELNET", "FTP")):
            analysis.append("  - WARNING: Unencrypted TELNET/FTP detected")
        else:
            analysis.append("  - No obvious insecure protocols detected in this sample")
        return "\n".join(analysis)
