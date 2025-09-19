# Claude Development Notes

This project was developed with assistance from Claude (Anthropic). This file documents the development process and key decisions made during implementation.

## Project Goals

Create a comprehensive network gateway security assessment tool that can:
- Quickly identify common router security issues
- Be easily run by non-technical users to assess friends/family networks
- Provide actionable security recommendations
- Discover modern network services (UPnP, mDNS, NAT-PMP, IPv6)

## Development Process

### Initial Implementation
- Started with basic router detection and port scanning
- Added vendor identification and default credential testing
- Implemented web interface discovery and analysis

### Enhanced Service Discovery
- Added UPnP/SSDP discovery with proper multicast implementation
- Implemented NAT-PMP detection using actual protocol requests
- Added IPv6 configuration analysis
- Created comprehensive mDNS service discovery with flag-based detailed scanning

### Key Technical Decisions

**UPnP Implementation:**
- Used proper SSDP multicast discovery instead of just port scanning
- Implemented SOAP-based port mapping enumeration to reveal security issues
- Added device fingerprinting via XML description parsing

**mDNS Discovery:**
- Implemented raw DNS packet construction for service queries
- Added flag-based comprehensive scanning (`--mdns`) vs basic detection
- Created security risk assessment for discovered services

**NAT-PMP Protocol:**
- Implemented actual NAT-PMP requests rather than just checking port accessibility
- Added proper response validation to confirm service availability

**Security Focus:**
- Prioritized discovery of information disclosure vulnerabilities
- Emphasized the security implications of each discovered service
- Created actionable recommendations based on findings

### Architecture Evolution

**Modular Design:**
- Started as monolithic `main.go`
- Refactored into modules: `upnp.go`, `mdns.go`
- Maintained shared types and clean interfaces

**Error Handling:**
- Implemented graceful degradation when services are unavailable
- Added timeouts and proper connection handling
- Created fallback methods for service detection

## Key Insights Discovered

### UPnP Security Issues
- UPnP port mapping enumeration reveals significant security information
- Any LAN device can query all active port forwards without authentication
- This creates reconnaissance opportunities for attackers

### mDNS Exposure
- Many IoT devices advertise detailed service information
- Home networks often have 20+ discoverable services
- Services like SSH, SMB, and printers may be inadvertently exposed

### NAT-PMP vs UPnP
- Many modern routers support both protocols simultaneously
- NAT-PMP is simpler but UPnP provides more detailed information
- Both enable automatic port forwarding with security implications

## Code Quality Considerations

### Go Best Practices
- Used proper error handling throughout
- Implemented timeouts for all network operations
- Created clean separation of concerns between modules

### Security Considerations
- Tool performs only read operations (no modifications)
- Implemented rate limiting and respectful scanning
- Added appropriate warnings about authorized use only

### Performance
- Used concurrent operations where appropriate
- Implemented efficient parsing for protocol responses
- Added configurable timeouts for different operations

## Testing Approach

### Real Network Testing
- Tested against UniFi Dream Machine with active services
- Validated against networks with various router vendors
- Confirmed detection accuracy across different configurations

### Protocol Compliance
- Verified SSDP multicast implementation against standards
- Tested NAT-PMP request/response format compliance
- Ensured mDNS queries follow RFC specifications

## Future Enhancements

### Potential Additions
- Support for more router vendors and models
- Additional protocol support (PCP, DLNA, etc.)
- JSON output format for automated processing
- Integration with vulnerability databases

### Architecture Improvements
- Consider plugin architecture for extensibility
- Add configuration file support
- Implement result caching for repeated scans

## Development Tools Used

### Go Ecosystem
- Standard library networking packages
- Flag package for command-line interface
- Regexp for pattern matching and parsing

### Testing and Validation
- Manual testing against real network infrastructure
- Protocol analysis using network capture tools
- Cross-reference with other security scanning tools

## Lessons Learned

### Network Programming
- Multicast programming requires careful socket handling
- Protocol implementation needs precise byte-level control
- Timeout handling is critical for network tools

### Security Tool Design
- Balance between comprehensive scanning and performance
- User-friendly output is crucial for adoption
- Clear severity levels help prioritize remediation

### Go Development
- Modular architecture scales well for network tools
- Standard library provides excellent networking primitives
- Error handling patterns are essential for robust tools

This project demonstrates effective use of Go for network security tools and showcases modern router service discovery techniques.

## MCP Integration Architecture

### Checker Package Structure (Issue #23)
- **Modular Checkers**: Each security check is now a separate package under `checkers/`
  - Example: `checkers/web/`, `checkers/ports/`, `checkers/upnp/`
  - Each checker implements the `internal/checker.Checker` interface
  - Shared types live in `checkers/common/`

- **Checker Interface**: Defined in `internal/checker/checker.go`
  ```go
  type Checker interface {
      Name() string
      Description() string
      Icon() string
      DefaultConfig() CheckerConfig
      RequiresRouter() bool
      DefaultEnabled() bool
      Run(config CheckerConfig, router *common.RouterInfo)
      RunStandalone(config CheckerConfig)
      MCPToolDefinition() *MCPTool
  }
  ```

- **Dynamic Registry**: The `checkers/registry.go` provides:
  - `AllCheckers()` - Returns all available checker implementations
  - `GetChecker(name)` - Lookup checker by name
  - `RunChecker(name, config, router)` - Execute a specific checker
  - Main.go builds its check registry dynamically from `checkers.AllCheckers()`

- **Dual Mode Operation**:
  - **CLI Mode** (default): Traditional command-line interface
  - **MCP Mode** (`--mcp` flag): Model Context Protocol server over stdio
  - Completely separate code paths dispatched from `main()`

- **Type Conversion**: Adapters in `mcp_adapters.go` convert between:
  - Legacy `main.RouterInfo` (for CLI compatibility)
  - New `common.RouterInfo` (for checker packages)
  - MCP input/output types

### Development Guidelines
- When building new checks, always put them in their own package under `checkers/`
- Each checker package should have a `doc.go` file
- Never put checker implementations in `main.go` - main.go only orchestrates
- The checker registry is built dynamically - add new checkers to `AllCheckers()` in `checkers/registry.go`
- Always commit and push before changing branches
- Never use the timeout command - it blocks command approval. Use Bash tool with background execution instead
- Do not use `&` to background a bash prompt - use the dedicated tool parameter