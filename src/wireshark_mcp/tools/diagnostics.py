"""Diagnostic MCP tools (expert info, filtered display) — TShark-only."""

from __future__ import annotations

import datetime
import os
import tempfile
from typing import Optional

from mcp.server.fastmcp import Context

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
    run_tshark,
)


def register(mcp) -> None:
    @mcp.tool(name="expert_information")
    def expert_information(
        interface: str = None,
        pcap_file: str = None,
        duration: int = 10,
        packet_count: Optional[int] = None,
        ctx: Context = None,
    ) -> str:
        """Display expert information (warnings, errors, notes) for captured traffic."""
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
                    f"expert_capture_{int(datetime.datetime.now().timestamp())}.pcap",
                )
                cap_result = capture_to_temp_pcap(
                    safe,
                    temp_pcap,
                    duration=duration,
                    packet_count=packet_count,
                )
                if not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                    return (
                        "Error capturing packets for expert information: "
                        f"{cap_result.stderr.strip() or 'empty capture'}"
                    )
                source = temp_pcap

            result = run_tshark(["-r", source, "-q", "-z", "expert"], timeout=60)
            combined = (result.stdout or "") + "\n" + (result.stderr or "")
            body = extract_stats_section(combined, "Expert Information")
            if not body:
                # expert table may use different headers
                body = combined.strip()
            if not body:
                return f"Error retrieving expert information: {result.stderr.strip()}"
            return "EXPERT INFORMATION\n==================\n\n" + body
        except Exception as exc:
            return f"Error in expert information: {exc}"
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass

    @mcp.tool(name="filtered_packet_display")
    def filtered_packet_display(
        display_filter: str,
        interface: str = None,
        pcap_file: str = None,
        duration: int = 10,
        packet_count: Optional[int] = None,
        include_hex: bool = False,
        ctx: Context = None,
    ) -> str:
        """Filter and display packets based on Wireshark display filter syntax."""
        if not interface and not pcap_file:
            return "Error: Either interface or pcap_file must be specified"
        disp, disp_err = validate_display_filter(display_filter)
        if disp_err:
            return disp_err
        if not disp:
            return "Error: Display filter must be specified"

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
                    f"filter_capture_{int(datetime.datetime.now().timestamp())}.pcap",
                )
                cap_result = capture_to_temp_pcap(
                    safe,
                    temp_pcap,
                    duration=duration,
                    packet_count=packet_count,
                )
                if not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                    return (
                        "Error capturing packets for filtered display: "
                        f"{cap_result.stderr.strip() or 'empty capture'}"
                    )
                source = temp_pcap

            args = ["-r", source, "-Y", disp, "-V"]
            if include_hex:
                args.append("-x")
            result = run_tshark(args, timeout=120)
            body = result.stdout
            if not body.strip():
                err = result.stderr.strip()
                return f"Error: no packets matched filter '{disp}'" + (
                    f" ({err})" if err else ""
                )

            frame_count = body.count("\nFrame ")
            header = (
                f"FILTERED PACKETS (Filter: {disp})\n"
                f"=======================================\n"
                f"Found {frame_count} matching packet(s)\n\n"
            )
            return header + body
        except Exception as exc:
            return f"Error in filtered packet display: {exc}"
        finally:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass
