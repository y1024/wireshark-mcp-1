"""
Advanced packet capture tools for the PyShark MCP server.
"""

from typing import Dict, List, Optional, Any, Tuple
import json
import time
import datetime
import os
import tempfile

# Try to import pyshark
try:
    import pyshark
except ImportError:
    print("Warning: PyShark library not found. This module will not function correctly.")


def capture_targeted_traffic(
    interface: str,
    target_host: str = None,
    target_port: int = None,
    protocol: str = None,
    duration: int = 30,
    packet_limit: int = 1000,
) -> Dict[str, Any]:
    """
    Capture traffic targeted to specific host, port, or protocol.
    
    Args:
        interface: Network interface to capture from
        target_host: Target host IP address
        target_port: Target port number
        protocol: Protocol filter (e.g., "tcp", "udp", "icmp", "http")
        duration: Maximum capture duration in seconds
        packet_limit: Maximum number of packets to capture
        
    Returns:
        Dictionary with capture results
    """
    # Build the capture filter
    filter_parts = []
    
    if target_host:
        filter_parts.append(f"host {target_host}")
    
    if target_port:
        filter_parts.append(f"port {target_port}")
    
    if protocol:
        # Convert common protocol names to filter syntax
        if protocol.lower() in ["http", "https"]:
            if protocol.lower() == "http":
                filter_parts.append("tcp port 80")
            else:
                filter_parts.append("tcp port 443")
        else:
            filter_parts.append(protocol.lower())
    
    # Combine filter parts with 'and'
    capture_filter = " and ".join(filter_parts) if filter_parts else ""
    
    # Create timestamp for this capture
    timestamp = datetime.datetime.now().isoformat()
    capture_id = f"targeted_{timestamp.replace(':', '-')}"
    
    try:
        # Create and run the capture
        cap = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)
        
        # Start time for tracking duration
        start_time = time.time()
        
        # Capture with either packet limit or time limit
        if packet_limit:
            packets = cap.sniff_continuously(packet_count=packet_limit)
            # Convert generator to list
            packet_list = list(packets)
        else:
            packet_list = []
            
            # Manually handle duration-based capture
            for packet in cap.sniff_continuously():
                packet_list.append(packet)
                
                # Check if we've reached the time limit
                if time.time() - start_time >= duration:
                    break
                    
                # Check if we've hit packet limit as a backup
                if len(packet_list) >= 1000:  # Hard limit to prevent unlimited capture
                    break
        
        # Process captured packets
        packet_count = len(packet_list)
        protocol_counts = {}
        ip_stats = {"sources": {}, "destinations": {}}
        
        for packet in packet_list:
            # Track protocol stats
            highest_layer = packet.highest_layer
            if highest_layer in protocol_counts:
                protocol_counts[highest_layer] += 1
            else:
                protocol_counts[highest_layer] = 1
                
            # Track IP stats if available
            if hasattr(packet, 'ip'):
                # Source IP tracking
                src_ip = packet.ip.src
                if src_ip in ip_stats["sources"]:
                    ip_stats["sources"][src_ip] += 1
                else:
                    ip_stats["sources"][src_ip] = 1
                    
                # Destination IP tracking
                dst_ip = packet.ip.dst
                if dst_ip in ip_stats["destinations"]:
                    ip_stats["destinations"][dst_ip] += 1
                else:
                    ip_stats["destinations"][dst_ip] = 1
        
        # Create the capture results
        capture_results = {
            "capture_id": capture_id,
            "timestamp": timestamp,
            "interface": interface,
            "filter": capture_filter,
            "target_host": target_host,
            "target_port": target_port,
            "protocol": protocol,
            "duration_seconds": time.time() - start_time,
            "packet_count": packet_count,
            "protocol_summary": protocol_counts,
            "ip_stats": ip_stats
        }
        
        return capture_results
        
    except Exception as e:
        return {
            "capture_id": capture_id,
            "timestamp": timestamp,
            "error": str(e),
            "interface": interface,
            "filter": capture_filter,
        }


def capture_to_file(
    interface: str,
    output_file: str,
    capture_filter: str = "",
    duration: int = 60,
    packet_limit: int = None,
) -> Dict[str, Any]:
    """
    Capture network traffic and save to a pcap file.
    
    Args:
        interface: Network interface to capture from
        output_file: Path where to save the pcap file
        capture_filter: BPF filter expression
        duration: Duration in seconds
        packet_limit: Maximum number of packets
        
    Returns:
        Dictionary with capture results
    """
    # Create timestamp for this capture
    timestamp = datetime.datetime.now().isoformat()
    capture_id = f"file_{timestamp.replace(':', '-')}"
    
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Create the capture
        cap = pyshark.LiveCapture(
            interface=interface, 
            bpf_filter=capture_filter,
            output_file=output_file
        )
        
        # Start time for tracking duration
        start_time = time.time()
        
        # Run the capture based on limits
        if packet_limit:
            cap.sniff(packet_count=packet_limit)
        else:
            cap.sniff(timeout=duration)
        
        # Get capture duration
        capture_duration = time.time() - start_time
        
        # Create summary without reading packets (file is already saved)
        capture_results = {
            "capture_id": capture_id,
            "timestamp": timestamp,
            "interface": interface,
            "output_file": output_file,
            "filter": capture_filter,
            "duration_seconds": capture_duration,
            "status": "completed"
        }
        
        return capture_results
        
    except Exception as e:
        return {
            "capture_id": capture_id,
            "timestamp": timestamp,
            "error": str(e),
            "interface": interface,
            "filter": capture_filter,
            "output_file": output_file,
            "status": "failed"
        }


def analyze_http_traffic(capture_file: str) -> Dict[str, Any]:
    """
    Analyze HTTP traffic from a capture file.
    
    Args:
        capture_file: Path to the pcap/pcapng file
        
    Returns:
        Dictionary with HTTP analysis
    """
    try:
        # Create the file capture with HTTP display filter
        cap = pyshark.FileCapture(capture_file, display_filter="http")
        
        # Process packets
        http_requests = []
        http_hosts = {}
        http_methods = {}
        http_status_codes = {}
        
        # Load packets
        packets = list(cap)
        
        for packet in packets:
            if hasattr(packet, 'http'):
                http_layer = packet.http
                
                # Process HTTP request
                if hasattr(http_layer, 'request'):
                    # Extract host
                    host = http_layer.host if hasattr(http_layer, 'host') else 'unknown'
                    if host in http_hosts:
                        http_hosts[host] += 1
                    else:
                        http_hosts[host] = 1
                    
                    # Extract method
                    method = http_layer.request_method if hasattr(http_layer, 'request_method') else 'unknown'
                    if method in http_methods:
                        http_methods[method] += 1
                    else:
                        http_methods[method] = 1
                    
                    # Track request details
                    uri = http_layer.request_uri if hasattr(http_layer, 'request_uri') else '/'
                    user_agent = http_layer.user_agent if hasattr(http_layer, 'user_agent') else 'unknown'
                    
                    http_requests.append({
                        'timestamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else 'unknown',
                        'method': method,
                        'host': host,
                        'uri': uri,
                        'user_agent': user_agent
                    })
                
                # Process HTTP response
                if hasattr(http_layer, 'response'):
                    # Extract status code
                    status_code = http_layer.response_code if hasattr(http_layer, 'response_code') else 'unknown'
                    if status_code in http_status_codes:
                        http_status_codes[status_code] += 1
                    else:
                        http_status_codes[status_code] = 1
        
        # Create analysis summary
        analysis = {
            "timestamp": datetime.datetime.now().isoformat(),
            "capture_file": capture_file,
            "http_requests_count": len(http_requests),
            "hosts": http_hosts,
            "methods": http_methods,
            "status_codes": http_status_codes,
            "requests": http_requests[:100]  # Limit to 100 requests to avoid huge results
        }
        
        return analysis
        
    except Exception as e:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "capture_file": capture_file,
            "error": str(e)
        }


def detect_network_protocols(
    capture_file: str = None,
    interface: str = None,
    duration: int = 30
) -> Dict[str, Any]:
    """
    Detect and report network protocols in use.
    
    Args:
        capture_file: Path to existing pcap file (optional)
        interface: Network interface to capture from (if no file provided)
        duration: Duration in seconds for live capture
        
    Returns:
        Dictionary with protocol detection results
    """
    protocol_summary = {}
    packet_count = 0
    
    try:
        # Determine if we're reading a file or doing live capture
        if capture_file:
            # File-based capture
            cap = pyshark.FileCapture(capture_file)
            packets = list(cap)
        else:
            # Live capture
            if not interface:
                return {"error": "Either capture_file or interface must be provided"}
                
            # Create temporary file for capture
            temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
            os.close(temp_fd)
            
            # Perform live capture
            cap = pyshark.LiveCapture(interface=interface, output_file=temp_path)
            cap.sniff(timeout=duration)
            
            # Read from temporary file
            file_cap = pyshark.FileCapture(temp_path)
            packets = list(file_cap)
            
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
        
        # Process packets for protocol detection
        packet_count = len(packets)
        layer_counts = {}
        application_protocols = {}
        
        for packet in packets:
            # Count each layer in the packet
            for layer in packet.layers:
                layer_name = layer.layer_name
                if layer_name in layer_counts:
                    layer_counts[layer_name] += 1
                else:
                    layer_counts[layer_name] = 1
            
            # Track highest layer as the application protocol
            if hasattr(packet, 'highest_layer'):
                app_proto = packet.highest_layer
                if app_proto in application_protocols:
                    application_protocols[app_proto] += 1
                else:
                    application_protocols[app_proto] = 1
        
        # Organize results
        protocol_summary = {
            "timestamp": datetime.datetime.now().isoformat(),
            "source": capture_file if capture_file else f"live capture on {interface}",
            "packet_count": packet_count,
            "layer_protocols": layer_counts,
            "application_protocols": application_protocols,
        }
        
        # Add insights section
        protocol_summary["insights"] = []
        
        # Identify common protocol patterns
        if "http" in application_protocols or "HTTP" in application_protocols:
            protocol_summary["insights"].append("Web traffic (HTTP) detected")
            
        if "tls" in application_protocols or "TLS" in application_protocols:
            protocol_summary["insights"].append("Encrypted web traffic (HTTPS/TLS) detected")
            
        if "dns" in application_protocols or "DNS" in application_protocols:
            protocol_summary["insights"].append("DNS queries detected")
            
        if "nbns" in application_protocols or "NBNS" in application_protocols:
            protocol_summary["insights"].append("NetBIOS name service detected - typically indicates Windows networks")
            
        if "ssdp" in application_protocols or "SSDP" in application_protocols:
            protocol_summary["insights"].append("UPnP device discovery (SSDP) detected")
            
        if "dhcp" in application_protocols or "DHCP" in application_protocols:
            protocol_summary["insights"].append("DHCP traffic detected - IP address assignment activity")
            
        return protocol_summary
        
    except Exception as e:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "source": capture_file if capture_file else f"live capture on {interface}",
            "error": str(e)
        }


def format_analysis_report(analysis: Dict[str, Any], format_type: str = "text") -> Tuple[str, str]:
    """
    Format analysis report for display.
    
    Args:
        analysis: Analysis dictionary
        format_type: Output format (text, json, html)
        
    Returns:
        Tuple of (data, mime_type)
    """
    if format_type.lower() == "json":
        return json.dumps(analysis, indent=2), "application/json"
    
    elif format_type.lower() == "html":
        # Basic HTML report
        html = ["<html><head><title>Network Analysis Report</title>"]
        html.append("<style>body{font-family:sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background-color:#f2f2f2}</style>")
        html.append("</head><body>")
        
        # Header
        html.append("<h1>Network Traffic Analysis Report</h1>")
        html.append(f"<p>Generated: {analysis.get('timestamp', 'Unknown')}</p>")
        
        # Source information
        if 'source' in analysis:
            html.append(f"<p>Source: {analysis['source']}</p>")
        elif 'capture_file' in analysis:
            html.append(f"<p>Capture File: {analysis['capture_file']}</p>")
        
        # Error handling
        if 'error' in analysis:
            html.append(f"<div style='color:red'><h2>Error</h2><p>{analysis['error']}</p></div>")
            html.append("</body></html>")
            return "\n".join(html), "text/html"
        
        # Packet summary
        html.append("<h2>Summary</h2>")
        html.append(f"<p>Total Packets: {analysis.get('packet_count', 'Unknown')}</p>")
        
        # Insights
        if 'insights' in analysis and analysis['insights']:
            html.append("<h2>Insights</h2><ul>")
            for insight in analysis['insights']:
                html.append(f"<li>{insight}</li>")
            html.append("</ul>")
        
        # Protocol information
        if 'application_protocols' in analysis:
            html.append("<h2>Application Protocols</h2>")
            html.append("<table><tr><th>Protocol</th><th>Count</th><th>Percentage</th></tr>")
            
            total = sum(analysis['application_protocols'].values())
            
            for proto, count in sorted(analysis['application_protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total) * 100 if total > 0 else 0
                html.append(f"<tr><td>{proto}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>")
                
            html.append("</table>")
        
        # HTTP specific information
        if 'http_requests_count' in analysis:
            html.append("<h2>HTTP Traffic</h2>")
            html.append(f"<p>Total HTTP Requests: {analysis['http_requests_count']}</p>")
            
            if 'hosts' in analysis and analysis['hosts']:
                html.append("<h3>Top Hosts</h3>")
                html.append("<table><tr><th>Host</th><th>Count</th></tr>")
                
                for host, count in sorted(analysis['hosts'].items(), key=lambda x: x[1], reverse=True):
                    html.append(f"<tr><td>{host}</td><td>{count}</td></tr>")
                    
                html.append("</table>")
            
            if 'methods' in analysis and analysis['methods']:
                html.append("<h3>HTTP Methods</h3>")
                html.append("<table><tr><th>Method</th><th>Count</th></tr>")
                
                for method, count in sorted(analysis['methods'].items(), key=lambda x: x[1], reverse=True):
                    html.append(f"<tr><td>{method}</td><td>{count}</td></tr>")
                    
                html.append("</table>")
        
        html.append("</body></html>")
        return "\n".join(html), "text/html"
    
    else:  # Default to text format
        lines = []
        lines.append("=== Network Traffic Analysis Report ===")
        lines.append(f"Generated: {analysis.get('timestamp', 'Unknown')}")
        lines.append("")
        
        # Source information
        if 'source' in analysis:
            lines.append(f"Source: {analysis['source']}")
        elif 'capture_file' in analysis:
            lines.append(f"Capture File: {analysis['capture_file']}")
        
        # Error handling
        if 'error' in analysis:
            lines.append("\nERROR:")
            lines.append(f"  {analysis['error']}")
            return "\n".join(lines), "text/plain"
        
        # Packet summary
        lines.append(f"\nTotal Packets: {analysis.get('packet_count', 'Unknown')}")
        
        # Insights
        if 'insights' in analysis and analysis['insights']:
            lines.append("\nInsights:")
            for insight in analysis['insights']:
                lines.append(f"  - {insight}")
        
        # Protocol information
        if 'application_protocols' in analysis:
            lines.append("\nApplication Protocols:")
            
            total = sum(analysis['application_protocols'].values())
            
            for proto, count in sorted(analysis['application_protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total) * 100 if total > 0 else 0
                lines.append(f"  - {proto}: {count} packets ({percentage:.1f}%)")
        
        # HTTP specific information
        if 'http_requests_count' in analysis:
            lines.append("\nHTTP Traffic:")
            lines.append(f"  Total HTTP Requests: {analysis['http_requests_count']}")
            
            if 'hosts' in analysis and analysis['hosts']:
                lines.append("\n  Top Hosts:")
                for host, count in sorted(analysis['hosts'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    lines.append(f"    - {host}: {count} requests")
            
            if 'methods' in analysis and analysis['methods']:
                lines.append("\n  HTTP Methods:")
                for method, count in sorted(analysis['methods'].items(), key=lambda x: x[1], reverse=True):
                    lines.append(f"    - {method}: {count}")
        
        return "\n".join(lines), "text/plain" 