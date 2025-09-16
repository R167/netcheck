# TODO List

## Planned Features

### Starlink Dishy Configuration Detection
- **Target**: Add support for detecting Starlink Dishy configuration via gRPC
- **Endpoint**: `192.168.100.1` (standard Starlink IP)
- **Protocol**: gRPC using protobuf definitions
- **Reference**: https://github.com/clarkzjw/starlink-grpc-golang
- **Implementation Notes**:
  - Check if route to 192.168.100.1 exists
  - Attempt gRPC connection to Starlink Dishy service
  - Extract configuration information and security settings
  - Add to security assessment if accessible
  - Handle cases where Starlink is not present on network
- **Branch**: Create `feature/starlink-support` branch for implementation
- **Testing**: Remote forward setup may be needed for testing

### Future Enhancements
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