# Wireshark MCP Server

This project exposes PyShark functionality through the Model Context Protocol (MCP), allowing AI assistants like Claude to interact with network packet capture and analysis capabilities.

## Installation

1. Install the required dependencies:

```bash
# Install with uv (recommended)
uv add mcp[cli] pyshark

# Or with pip
pip install mcp[cli] pyshark
```

2. Clone this repository:

```bash
git clone https://github.com/A-G-U-P-T-A/wireshark-mcp
cd wireshark-mcp
```

## Requirements

- Python 3.8+
- TShark (Wireshark's command-line component) must be installed
- Administrative/root privileges for live packet capture

## Usage

### Running the server

You can run the server in development mode with the MCP Inspector:

```bash
mcp dev pyshark_mcp.py
```

Or install it directly in Claude Desktop:

```bash
mcp install pyshark_mcp.py
```

### Available functionality

This MCP server exposes the following:

#### Resources

- `pyshark://version` - Gets the PyShark version information
- `pyshark://config` - Gets the PyShark configuration
- `pyshark://capture-history` - Gets history of previous packet captures

#### Tools

- `list_interfaces` - Lists all available network interfaces
- `capture_live_packets` - Captures live packets from a network interface
- `read_pcap_file` - Reads and analyzes a packet capture file
- `analyze_traffic` - Analyzes network traffic patterns from a capture

Advanced tools provided in `advanced_captures.py`:

- `capture_targeted_traffic` - Captures traffic targeted to specific host, port, or protocol
- `capture_to_file` - Captures network traffic and saves to a pcap file
- `analyze_http_traffic` - Analyzes HTTP traffic from a capture file
- `detect_network_protocols` - Detects and reports network protocols in use

#### Prompts

- `packet_capture_help` - Provides help information about packet capturing with PyShark

## Example usage in Claude

Once the server is installed in Claude Desktop, you can interact with it like this:

```
You: What interfaces are available for network capture?

Claude: Let me check the available network interfaces on your system.
[Calls list_interfaces tool]

You: Can you capture HTTP traffic for 10 seconds?

Claude: I'll capture HTTP traffic for 10 seconds.
[Calls capture_live_packets with appropriate parameters]

You: Can you analyze the traffic I just captured?

Claude: Here's an analysis of the captured traffic:
[Calls analyze_traffic to provide insights]

Remember to always ensure you have permission to capture network traffic.
```

## Security Considerations

Network packet capture is a sensitive operation. Please ensure:

1. You have proper authorization to capture network traffic
2. You comply with all applicable laws and regulations
3. You don't capture sensitive or private data inadvertently
4. You handle capture files securely to prevent unauthorized access

## Requirements

- **PyShark**: Python wrapper for TShark
- **TShark**: Command-line version of Wireshark (must be installed separately)
- **Administrative privileges**: Often required for live packet capture

## Customization

You can customize this MCP server by:

1. Adding more advanced capture and analysis tools
2. Implementing filters for specific traffic types
3. Creating specialized analysis functions for protocols of interest
4. Extending the capture history management capabilities