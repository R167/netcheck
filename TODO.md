# TODO List

## Completed Features

### ✅ Starlink Dishy Configuration Detection (Completed)
- **Status**: ✅ COMPLETED - Implemented in `feature/starlink-support` branch
- **Implementation**: Complete Starlink gRPC scanner with security assessment
- **Features Added**:
  - gRPC client using grpcurl for communication with Starlink API
  - Device information extraction (hardware, software, device ID)
  - Operational status monitoring (performance, uptime, signal strength)
  - Configuration analysis (update policies, power management)
  - Comprehensive security assessment with multiple severity levels
  - Beautiful reporting with detailed metrics and recommendations
  - Support for both standard (192.168.100.1:9200) and test endpoints
  - Graceful handling when Starlink not present on network

## Future Enhancements
- Support for more ISP-specific router models
- JSON output format for automated processing
- Plugin architecture for extensible scanning
- Integration with vulnerability databases
- Enhanced IPv6 discovery and analysis
- Wireless security assessment (WPA/WPA2/WPA3)
- Firmware version detection and CVE checking

### Code Quality Improvements
- Additional unit tests
- Integration test suite
- Performance optimization for large networks
- Configuration file support
- Logging framework integration