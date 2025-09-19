# netcheck

A comprehensive network gateway security assessment tool for identifying vulnerabilities in home and small office routers.

## Features

- **Gateway Discovery**: Automatically detects your network gateway
- **Service Detection**: Identifies UPnP, NAT-PMP, mDNS, and other network services
- **Security Analysis**: Tests for default credentials, exposed services, and misconfigurations
- **Port Mapping Enumeration**: Discovers active UPnP port forwards
- **Device Fingerprinting**: Identifies router vendor, model, and serial numbers
- **IPv6 Assessment**: Checks IPv6 configuration and potential firewall bypasses
- **Comprehensive Reporting**: Prioritized security issues with actionable recommendations
- **MCP Support**: Model Context Protocol server mode for AI agent integration

## Detectors

| Detector | Flag | Default | Description |
|----------|------|---------|-------------|
| **Web Interface** | `--web` | ✅ | Tests router web interface, detects vendor, and checks default credentials |
| **Port Scanning** | `--ports` | ✅ | Scans common management ports (SSH, HTTP, HTTPS, SNMP, etc.) |
| **UPnP Discovery** | `--upnp` | ✅ | Discovers UPnP services and enumerates active port mappings |
| **NAT-PMP** | `--natpmp` | ✅ | Detects NAT-PMP services for automatic port mapping |
| **IPv6 Analysis** | `--ipv6` | ✅ | Analyzes IPv6 configuration and connectivity |
| **API Discovery** | `--api` | ✅ | Checks for exposed router APIs and CGI scripts |
| **mDNS Discovery** | `--mdns` | 🔧 | Comprehensive mDNS/Bonjour service discovery |
| **Starlink Detection** | `--starlink` | 🔧 | Specialized Starlink Dishy detection |
| **Routing Info** | `--routes` | 🔧 | Displays routing table information |
| **Device Info** | `--device` | 🔧 | Shows network interface and device information |
| **External IP** | `--external` | 🔧 | Discovers external IPv4/IPv6 addresses |
| **LLDP Discovery** | `--lldp` | 🔧 | Link Layer Discovery Protocol analysis |

### Special Flags

| Flag | Description |
|------|-------------|
| `--all` | Run all available detectors |
| `--default` | Run only the default detector suite |
| `--mcp` | Run in MCP (Model Context Protocol) server mode |
| `--show-virtual` | Include virtual network interfaces (VPN tunnels, Docker bridges, etc.) |
| `--proxy` | Test proxy configuration (requires `--external`) |

**Legend**: ✅ = Enabled by default, 🔧 = Flag required

## Quick Start

Try netcheck without installation:

```bash
go run github.com/R167/netcheck@latest
```

## Installation

```bash
git clone https://github.com/R167/netcheck.git
cd netcheck
go build -o netcheck
```

## Usage

### Basic Security Scan
```bash
./netcheck
```

### Run Specific Detectors
```bash
./netcheck --mdns              # mDNS service discovery
./netcheck --external --proxy  # External IP with proxy testing
./netcheck --all               # All available tests
```

### MCP Server Mode

Run netcheck as an MCP server for integration with AI agents and tools:

```bash
./netcheck --mcp
```

Available MCP tools:
- `check_web_interface` - Test router web interface and default credentials
- `scan_ports` - Scan common management ports
- `check_all` - Run comprehensive security assessment

Each tool accepts a `gateway_ip` parameter and returns structured security findings.

## Example Output

```
🔍 Network Gateway Security Checker
====================================
🌐 Gateway IP: 192.168.1.1

🔍 Checking web interface...
  📱 Detected vendor: Netgear
  🔐 Testing default credentials for netgear...
  🚨 Default credentials work: admin/password

🔍 Checking UPnP services...
  📡 UPnP SSDP discovered
  📄 Device: Netgear R7000 (NETGEAR, Inc.)
  🔓 Found 3 port mapping(s)
    *:80 → 192.168.1.100:80 (TCP)
    *:22 → 192.168.1.50:22 (TCP)

📊 Security Assessment Report
=============================
Vendor: Netgear
Model: R7000
Issues Found: 3

🚨 Security Issues:
1. 🚨 [CRITICAL] Default credentials are active
   Username: 'admin', Password: 'password'

2. ⚠️ [HIGH] Active UPnP port mappings detected
   Found 3 active port forwarding rules that may expose internal services

3. 🔶 [MEDIUM] UPnP service is enabled
   UPnP can expose internal services and allow port forwarding
```

## Security Analysis

The tool performs comprehensive security analysis including:

- **Default Credentials**: Tests vendor-specific default login combinations
- **Service Discovery**: UPnP/SSDP, NAT-PMP, mDNS/Bonjour, IPv6 configuration
- **Port Scanning**: Common management ports (SSH, HTTP, HTTPS, SNMP, Telnet)
- **API Enumeration**: Router APIs, CGI scripts, WPS configuration
- **Device Fingerprinting**: Vendor, model, and serial number identification

## Supported Vendors

Linksys, Netgear, D-Link, TP-Link, ASUS, Cisco, Belkin, Motorola, and others.

## Security Issues

Issues are categorized by severity:

- **🚨 Critical**: Default credentials, exposed admin interfaces
- **⚠️ High**: Active UPnP port mappings, Telnet exposure, exposed CGI scripts
- **🔶 Medium**: UPnP/NAT-PMP enabled, SSH exposure, IPv6 issues, WPS enabled
- **ℹ️ Low**: mDNS exposure, information disclosure

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is intended for security assessment of networks you own or have explicit permission to test. Users are responsible for complying with all applicable laws and regulations.