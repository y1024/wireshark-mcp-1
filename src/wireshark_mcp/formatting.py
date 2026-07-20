"""Output formatters for capture and analysis tools."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import json

def format_capture_summary(summary: Dict[str, Any]) -> str:
    """
    Format capture summary into a readable string
    
    Args:
        summary: Capture summary dictionary
        
    Returns:
        Formatted summary string
    """
    output = []
    output.append(f"Capture ID: {summary.get('capture_id', 'Unknown')}")
    output.append(f"Timestamp: {summary.get('timestamp', 'Unknown')}")
    
    if 'interface' in summary:
        output.append(f"Interface: {summary['interface']}")
    
    if 'file_path' in summary:
        output.append(f"File: {summary['file_path']}")
    
    output.append(f"Filter: {summary.get('filter', 'None')}")
    output.append(f"Packet Count: {summary.get('packet_count', 0)}")
    
    if 'protocol_summary' in summary and summary['protocol_summary']:
        output.append("\nProtocol Distribution:")
        for protocol, count in summary['protocol_summary'].items():
            percentage = (count / summary['packet_count']) * 100
            output.append(f"  - {protocol}: {count} packets ({percentage:.1f}%)")
    
    return "\n".join(output)

def format_quick_capture(capture_id, interface, packet_count, protocols, packets):
    """Format quick capture results into a readable string"""
    
    output = []
    output.append(f"Quick Capture ID: {capture_id}")
    output.append(f"Interface: {interface}")
    output.append(f"Packet Count: {packet_count}")
    
    if protocols:
        output.append("\nProtocol Distribution:")
        for protocol, count in protocols.items():
            percentage = (count / packet_count) * 100
            output.append(f"  - {protocol}: {count} packets ({percentage:.1f}%)")
    
    # Extract source/destination statistics
    if packets:
        src_ips = {}
        dst_ips = {}
        
        for packet in packets:
            src = packet.get("src", "")
            dst = packet.get("dst", "")
            
            if src:
                src_ips[src] = src_ips.get(src, 0) + 1
            if dst:
                dst_ips[dst] = dst_ips.get(dst, 0) + 1
        
        # Show top source IPs
        if src_ips:
            output.append("\nTop Source IPs:")
            for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                output.append(f"  - {ip}: {count} packets")
                
        # Show top destination IPs
        if dst_ips:
            output.append("\nTop Destination IPs:")
            for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                output.append(f"  - {ip}: {count} packets")
    
    return "\n".join(output)

def format_deep_analysis(capture_id: str, interface: str, duration: int, 
                          packets: List[Dict[str, Any]], include_details: bool, 
                          max_packet_display: int = 1000) -> str:
    """
    Format deep analysis results with tabular data
    
    Args:
        capture_id: Unique identifier for this capture
        interface: Network interface used for capture
        duration: Duration of capture in seconds
        packets: List of packet dictionaries
        include_details: Whether to include detailed packet listing
        max_packet_display: Maximum number of packets to display in the details table (default: 1000)
    
    Returns:
        Formatted analysis text
    """
    from collections import Counter
    import ipaddress
    
    # Start with header
    output = [
        f"# Deep Packet Analysis Results",
        f"**Capture ID**: {capture_id}",
        f"**Interface**: {interface}",
        f"**Duration**: {duration} seconds",
        f"**Packets Analyzed**: {len(packets)}",
        ""
    ]
    
    # Protocol distribution
    protocol_counts = Counter(p["protocol"] for p in packets if p["protocol"])
    
    output.append("## Protocol Distribution")
    output.append("| Protocol | Count | Percentage |")
    output.append("|----------|-------|------------|")
    
    for protocol, count in protocol_counts.most_common():
        percentage = (count / len(packets)) * 100
        output.append(f"| {protocol} | {count} | {percentage:.1f}% |")
        
    output.append("")
    
    # IP Statistics
    src_ips = Counter(p["src_ip"] for p in packets if p["src_ip"])
    dst_ips = Counter(p["dst_ip"] for p in packets if p["dst_ip"])
    
    # Identify local vs external IPs
    local_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16")
    ]
    
    def is_local_ip(ip_str):
        if not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in local_networks)
        except ValueError:
            return False
    
    # Categorize traffic
    internal_traffic = sum(1 for p in packets if p["src_ip"] and p["dst_ip"] and 
                           is_local_ip(p["src_ip"]) and is_local_ip(p["dst_ip"]))
                           
    outbound_traffic = sum(1 for p in packets if p["src_ip"] and p["dst_ip"] and 
                           is_local_ip(p["src_ip"]) and not is_local_ip(p["dst_ip"]))
                           
    inbound_traffic = sum(1 for p in packets if p["src_ip"] and p["dst_ip"] and 
                          not is_local_ip(p["src_ip"]) and is_local_ip(p["dst_ip"]))
    
    # Traffic Direction
    output.append("## Traffic Direction")
    output.append("| Direction | Count | Percentage |")
    output.append("|-----------|-------|------------|")
    
    if len(packets) > 0:
        output.append(f"| Internal | {internal_traffic} | {internal_traffic/len(packets)*100:.1f}% |")
        output.append(f"| Outbound | {outbound_traffic} | {outbound_traffic/len(packets)*100:.1f}% |")
        output.append(f"| Inbound | {inbound_traffic} | {inbound_traffic/len(packets)*100:.1f}% |")
    
    output.append("")
    
    # Top Talkers
    output.append("## Top Source IPs")
    output.append("| IP Address | Count | Percentage | Type |")
    output.append("|------------|-------|------------|------|")
    
    for ip, count in src_ips.most_common(10):
        percentage = (count / len(packets)) * 100
        ip_type = "Local" if is_local_ip(ip) else "External"
        output.append(f"| {ip} | {count} | {percentage:.1f}% | {ip_type} |")
    
    output.append("")
    
    # Top Destinations
    output.append("## Top Destination IPs")
    output.append("| IP Address | Count | Percentage | Type |")
    output.append("|------------|-------|------------|------|")
    
    for ip, count in dst_ips.most_common(10):
        percentage = (count / len(packets)) * 100
        ip_type = "Local" if is_local_ip(ip) else "External"
        output.append(f"| {ip} | {count} | {percentage:.1f}% | {ip_type} |")
    
    output.append("")
    
    # Port Statistics
    src_ports = Counter(p["src_port"] for p in packets if p["src_port"])
    dst_ports = Counter(p["dst_port"] for p in packets if p["dst_port"])
    
    # Service port mapping
    common_ports = {
        "80": "HTTP",
        "443": "HTTPS",
        "53": "DNS",
        "22": "SSH",
        "25": "SMTP",
        "110": "POP3",
        "143": "IMAP",
        "123": "NTP",
        "21": "FTP",
        "23": "Telnet",
        "3389": "RDP",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "1433": "MS SQL",
        "8080": "HTTP-ALT"
    }
    
    # Most used destination ports
    output.append("## Most Used Destination Ports")
    output.append("| Port | Service | Count | Percentage |")
    output.append("|------|---------|-------|------------|")
    
    for port, count in dst_ports.most_common(10):
        percentage = (count / len(packets)) * 100
        service = common_ports.get(port, "Unknown")
        output.append(f"| {port} | {service} | {count} | {percentage:.1f}% |")
    
    output.append("")
    
    # Security Observations
    output.append("## Security Observations")
    security_findings = []
    
    # Check for unencrypted services
    unencrypted_ports = set(["21", "23", "80", "110"])
    used_unencrypted = [port for port in unencrypted_ports if port in dst_ports]
    
    if used_unencrypted:
        services = [f"{port} ({common_ports.get(port, 'Unknown')})" for port in used_unencrypted]
        security_findings.append(f"Unencrypted services detected: {', '.join(services)}")
    
    # Check for unusual ports
    high_ports = [port for port, count in dst_ports.items() 
                  if int(port) > 1024 and int(port) not in [8080, 8443] and count > 2]
                  
    if high_ports and len(high_ports) < 5:  # Only report if it's not too noisy
        security_findings.append(f"Unusual high ports with significant traffic: {', '.join(high_ports)}")
    
    # Check protocol anomalies
    if "ICMP" in protocol_counts and protocol_counts["ICMP"] > 10:
        security_findings.append(f"High ICMP traffic ({protocol_counts['ICMP']} packets) - potential ping scan")
    
    # Report findings or "all clear"
    if security_findings:
        for finding in security_findings:
            output.append(f"- âš ï¸ {finding}")
    else:
        output.append("- âœ… No obvious security issues detected in this capture")
    
    output.append("")
    
    # Packet Details Table (if requested)
    if include_details and packets:
        output.append("## Detailed Packet Capture")
        output.append("| # | Time | Source | Destination | Protocol | Length | Info |")
        output.append("|---|------|--------|-------------|----------|--------|------|")
        
        # Sort packets by time
        sorted_packets = sorted(packets, key=lambda p: float(p["time"]))
        
        # Display all packets up to max_packet_display limit
        display_count = min(len(sorted_packets), max_packet_display)
        
        for packet in sorted_packets[:display_count]:
            source = f"{packet['src_ip']}"
            if packet["src_port"]:
                source += f":{packet['src_port']}"
                
            destination = f"{packet['dst_ip']}"
            if packet["dst_port"]:
                destination += f":{packet['dst_port']}"
                
            # Truncate info if too long
            info = packet["info"]
            if info and len(info) > 50:
                info = info[:47] + "..."
                
            output.append(f"| {packet['num']} | {packet['time']} | {source} | {destination} | {packet['protocol']} | {packet['length']} | {info} |")
        
        if len(sorted_packets) > display_count:
            output.append(f"_(Table truncated to {display_count} packets)_")
    
    return "\n".join(output)

def format_http_analysis(capture_id: str, interface: str, duration: int,
                         http_packets: List[Dict[str, Any]], 
                         https_packets: List[Dict[str, Any]],
                         include_https: bool) -> str:
    """Format HTTP traffic analysis results with tabular data"""
    from collections import Counter, defaultdict
    
    # Start with header
    output = [
        f"# HTTP Traffic Analysis Results",
        f"**Capture ID**: {capture_id}",
        f"**Interface**: {interface}",
        f"**Duration**: {duration} seconds",
        f"**HTTP Packets**: {len(http_packets)}",
        f"**HTTPS Packets**: {len(https_packets)}",
        ""
    ]
    
    # HTTP request methods
    http_methods = Counter(p["method"] for p in http_packets if p["method"])
    
    if http_methods:
        output.append("## HTTP Methods")
        output.append("| Method | Count | Percentage |")
        output.append("|--------|-------|------------|")
        
        total_methods = sum(http_methods.values())
        for method, count in http_methods.most_common():
            percentage = (count / total_methods) * 100
            output.append(f"| {method} | {count} | {percentage:.1f}% |")
            
        output.append("")
    
    # HTTP response codes
    response_codes = Counter(p["response_code"] for p in http_packets if p["response_code"])
    
    if response_codes:
        output.append("## HTTP Response Codes")
        output.append("| Code | Description | Count | Percentage |")
        output.append("|------|-------------|-------|------------|")
        
        # HTTP status code descriptions
        status_descriptions = {
            "100": "Continue",
            "200": "OK",
            "201": "Created",
            "204": "No Content",
            "301": "Moved Permanently",
            "302": "Found",
            "304": "Not Modified",
            "400": "Bad Request",
            "401": "Unauthorized",
            "403": "Forbidden",
            "404": "Not Found",
            "500": "Internal Server Error",
            "502": "Bad Gateway",
            "503": "Service Unavailable"
        }
        
        total_responses = sum(response_codes.values())
        for code, count in response_codes.most_common():
            description = status_descriptions.get(code, "Unknown")
            percentage = (count / total_responses) * 100
            output.append(f"| {code} | {description} | {count} | {percentage:.1f}% |")
            
        output.append("")
    
    # Top hosts/domains
    hosts = Counter(p["host"] for p in http_packets if p["host"])
    
    if include_https:
        # Add SNI records from TLS handshakes
        for packet in https_packets:
            if packet["tls_sni"]:
                hosts[packet["tls_sni"]] += 1
    
    if hosts:
        output.append("## Top Domains")
        output.append("| Domain | Count | Percentage |")
        output.append("|--------|-------|------------|")
        
        total_hosts = sum(hosts.values())
        for host, count in hosts.most_common(10):  # Show top 10
            percentage = (count / total_hosts) * 100
            output.append(f"| {host} | {count} | {percentage:.1f}% |")
            
        output.append("")
    
    # Content types
    content_types = Counter(p["content_type"] for p in http_packets if p["content_type"])
    
    if content_types:
        output.append("## Content Types")
        output.append("| Content Type | Count | Percentage |")
        output.append("|-------------|-------|------------|")
        
        total_contents = sum(content_types.values())
        for ctype, count in content_types.most_common():
            # Truncate very long content types
            if len(ctype) > 40:
                ctype = ctype[:37] + "..."
                
            percentage = (count / total_contents) * 100
            output.append(f"| {ctype} | {count} | {percentage:.1f}% |")
            
        output.append("")
    
    # User Agents
    user_agents = Counter(p["user_agent"] for p in http_packets if p["user_agent"])
    
    if user_agents:
        output.append("## User Agents")
        output.append("| User Agent | Count | Percentage |")
        output.append("|------------|-------|------------|")
        
        total_agents = sum(user_agents.values())
        for agent, count in user_agents.most_common():
            # Truncate very long user agents
            if len(agent) > 50:
                agent = agent[:47] + "..."
                
            percentage = (count / total_agents) * 100
            output.append(f"| {agent} | {count} | {percentage:.1f}% |")
            
        output.append("")
    
    # Top URIs
    uris = Counter(p["uri"] for p in http_packets if p["uri"])
    
    if uris:
        output.append("## Top URIs")
        output.append("| URI | Count |")
        output.append("|-----|-------|")
        
        for uri, count in uris.most_common(10):  # Show top 10
            # Truncate very long URIs
            if len(uri) > 50:
                uri = uri[:47] + "..."
                
            output.append(f"| {uri} | {count} |")
            
        output.append("")
    
    # HTTPS/TLS Analysis (if included)
    if include_https and https_packets:
        output.append("## HTTPS/TLS Traffic")
        
        # TLS versions
        tls_versions = Counter(p["protocol"] for p in https_packets if p["protocol"])
        
        if tls_versions:
            output.append("### TLS Versions")
            output.append("| Version | Count | Percentage |")
            output.append("|---------|-------|------------|")
            
            total_tls = sum(tls_versions.values())
            for version, count in tls_versions.most_common():
                percentage = (count / total_tls) * 100
                output.append(f"| {version} | {count} | {percentage:.1f}% |")
                
            output.append("")
        
        # Handshake types
        handshake_types = Counter(p["tls_handshake_type"] for p in https_packets if p["tls_handshake_type"])
        
        if handshake_types:
            # Handshake type descriptions
            handshake_descriptions = {
                "1": "Client Hello",
                "2": "Server Hello",
                "11": "Certificate",
                "12": "Server Key Exchange",
                "16": "Client Key Exchange"
            }
            
            output.append("### TLS Handshakes")
            output.append("| Type | Description | Count |")
            output.append("|------|-------------|-------|")
            
            for htype, count in handshake_types.most_common():
                description = handshake_descriptions.get(htype, "Unknown")
                output.append(f"| {htype} | {description} | {count} |")
                
            output.append("")
    
    # Security analysis
    output.append("## Security Analysis")
    security_findings = []
    
    # Check for plain HTTP usage
    if http_packets:
        # Look for potentially sensitive URLs
        sensitive_patterns = ["login", "auth", "password", "signin", "signup", "account", "payment", "checkout"]
        sensitive_urls = []
        
        for packet in http_packets:
            if packet["uri"]:
                for pattern in sensitive_patterns:
                    if pattern in packet["uri"].lower():
                        sensitive_urls.append(f"{packet['host']}{packet['uri']}")
                        break
        
        if sensitive_urls:
            security_findings.append(f"Sensitive information sent over plain HTTP: {', '.join(set(sensitive_urls[:3]))}")
        
        # Check for HTTP errors
        error_codes = [code for code, count in response_codes.items() if code.startswith("4") or code.startswith("5")]
        if error_codes:
            security_findings.append(f"HTTP error status codes detected: {', '.join(error_codes)}")
    
    # Report findings
    if security_findings:
        for finding in security_findings:
            output.append(f"- âš ï¸ {finding}")
    else:
        output.append("- âœ… No obvious HTTP security issues detected")
    
    output.append("")
    
    # HTTP Traffic table
    if http_packets:
        output.append("## HTTP Requests/Responses")
        output.append("| # | Time | Method | Host | URI | Response |")
        output.append("|---|------|--------|------|-----|----------|")
        
        # Display first 20 HTTP packets max
        for packet in sorted(http_packets, key=lambda p: float(p["time"]))[:20]:
            method = packet["method"] or "-"
            host = packet["host"] or "-"
            uri = packet["uri"] or "-"
            response = packet["response_code"] or "-"
            
            # Truncate long fields
            if len(uri) > 30:
                uri = uri[:27] + "..."
            if len(host) > 20:
                host = host[:17] + "..."
                
            output.append(f"| {packet['num']} | {packet['time']} | {method} | {host} | {uri} | {response} |")
            
        if len(http_packets) > 20:
            output.append("_(Table truncated to 20 packets)_")
            
        output.append("")
    
    return "\n".join(output)

def format_analysis_report(analysis: Dict[str, Any], format_type: str = "text") -> Tuple[str, str]:
    """Delegate to advanced_captures formatter."""
    from wireshark_mcp.advanced_captures import format_analysis_report as _fmt
    return _fmt(analysis, format_type)
