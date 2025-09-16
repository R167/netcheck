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

### Comprehensive mDNS Service Discovery
```bash
./netcheck --mdns
```

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

## Security Checks

### Router Interface Analysis
- Default setup page detection
- Vendor identification via page content
- Title and content analysis

### Credential Testing
- Vendor-specific default credential databases
- HTTP Basic Authentication testing
- Common router login combinations

### Service Discovery
- **UPnP/SSDP**: Internet Gateway Device discovery and port mapping enumeration
- **NAT-PMP**: Network Address Translation Port Mapping Protocol detection
- **mDNS/Bonjour**: Multicast DNS service discovery (with `--mdns` flag)
- **IPv6**: Configuration analysis and gateway accessibility

### Port Scanning
- Common management ports (SSH, Telnet, HTTP, HTTPS, SNMP)
- Service-specific security assessments
- Protocol exposure analysis

### API Enumeration
- Common router API endpoints
- CGI script discovery
- Remote management interface detection
- WPS (WiFi Protected Setup) configuration checks

## Supported Router Vendors

- Linksys
- Netgear
- D-Link
- TP-Link
- ASUS
- Cisco
- Belkin
- Motorola

## Security Issues Detected

### Critical
- Active default credentials
- Exposed administrative interfaces

### High
- Active UPnP port mappings
- Telnet service exposure
- Exposed CGI scripts/remote management

### Medium
- UPnP/NAT-PMP services enabled
- SSH service exposure
- IPv6 configuration issues
- WPS enabled
- SNMP exposure

### Low
- mDNS service exposure
- General information disclosure

## Architecture

The tool is built with a modular architecture:

- `main.go`: Core logic and basic security functions
- `upnp.go`: UPnP/SSDP discovery and port mapping enumeration
- `mdns.go`: mDNS service discovery and analysis

## Use Cases

- **Home Network Security**: Quick assessment of family/friends' router security
- **Security Auditing**: Professional network security assessments
- **IoT Security**: Discovery of exposed devices and services
- **Network Documentation**: Inventory of active services and configurations

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is intended for security assessment of networks you own or have explicit permission to test. Users are responsible for complying with all applicable laws and regulations.