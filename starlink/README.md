# Starlink API Client

This package provides a Go client for interacting with Starlink Dishy terminals via their gRPC API.

## Implementation Approach

The client uses the `grpcurl` command-line tool to interact with the Starlink gRPC API. While this requires an external dependency, it's much simpler and more reliable than implementing a full gRPC client with protobuf generation.

### Why grpcurl instead of generated protobuf client?

1. **Simplicity**: No need to maintain proto files or generate code
2. **Reliability**: grpcurl handles all the gRPC reflection and protobuf encoding/decoding
3. **Maintenance**: No need to update proto definitions when Starlink changes their API
4. **Flexibility**: Works with any gRPC service that supports reflection

## Key Improvements Made

The original implementation had race conditions and reliability issues:

- **Race condition fix**: Removed conflicting timeouts between Go context (10s) and grpcurl (5s)
- **Consistent timeouts**: Both Go context and grpcurl use 8-second timeouts with proper coordination
- **Better error handling**: Graceful degradation when optional calls (status/config) fail
- **Connection validation**: TCP connectivity test before attempting gRPC calls

## How to Extract Proto Files (for reference/future changes)

If you need to understand the API structure or generate proper proto clients:

```bash
# Create output directory
mkdir -p starlink/proto

# Extract all proto definitions using grpcurl reflection
grpcurl -plaintext -proto-out-dir starlink/proto 127.0.0.1:9200 describe SpaceX.API.Device.Device

# The proto files will be saved to starlink/proto/ with proper package structure
```

This will generate:
- `spacex_api/device/device.proto` - Main service definition
- `spacex_api/device/common.proto` - Common message types
- `spacex_api/common/status/status.proto` - Status definitions
- Plus all dependencies

## Generating Go Client (if needed)

If you want to generate a proper Go client from proto files:

```bash
# Install protobuf tools
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code (after fixing go_package options)
cd starlink
protoc --go_out=. --go-grpc_out=. --proto_path=proto \
  proto/spacex_api/device/device.proto \
  proto/spacex_api/device/common.proto \
  proto/spacex_api/common/status/status.proto
```

**Note**: You'll need to add `option go_package = "spacex.com/api/...";` to proto files that don't have it.

## API Endpoints

The client currently implements:

- `GetDeviceInfo()` - Retrieves hardware/software information
- `GetStatus()` - Retrieves operational status (placeholder)
- `GetConfig()` - Retrieves configuration (placeholder)

### Adding New Endpoints

To add support for additional Starlink API calls:

1. Identify the gRPC method using: `grpcurl -plaintext 127.0.0.1:9200 describe SpaceX.API.Device.Request`
2. Find the field number for your request type
3. Create a similar method to `GetDeviceInfo()` with the appropriate request JSON

Example for getting status:
```go
requestData := `{"get_status":{}}`
// ... rest same as GetDeviceInfo()
```

## Dependencies

- Requires `grpcurl` binary to be available in PATH
- Go gRPC dependencies (for connection management)

## Security Considerations

The Starlink API provides access to sensitive device information including:
- Device identifiers
- Network configuration
- Performance metrics
- Operational status

Ensure this client is only used in trusted environments and consider the security implications of exposing this data.