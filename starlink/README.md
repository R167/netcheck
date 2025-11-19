# Starlink API Client

This package provides a Go client for interacting with Starlink Dishy terminals via their gRPC API.

## Implementation Approach

The client uses native Go gRPC with reflection to interact with the Starlink gRPC API. This provides a robust, dependency-free solution without requiring external tools or pre-generated protobuf code.

### Why native gRPC with reflection?

1. **No external dependencies**: Pure Go implementation, no need for grpcurl binary
2. **Reliability**: Direct gRPC connection with proper error handling
3. **Maintenance**: Uses reflection to dynamically discover API structure
4. **Performance**: Native implementation is faster than shelling out to external tools
5. **Flexibility**: Works with any gRPC service that supports reflection

## Key Features

- **Dynamic service discovery**: Uses gRPC reflection to discover service methods and message types
- **Proper timeout handling**: Consistent 10-second timeouts with context cancellation
- **Graceful error handling**: Detailed error messages and fallback parsing strategies
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

- `google.golang.org/grpc` - gRPC client library
- `google.golang.org/grpc/reflection/grpc_reflection_v1alpha` - gRPC reflection support
- `google.golang.org/protobuf` - Protocol Buffers runtime

## Security Considerations

The Starlink API provides access to sensitive device information including:
- Device identifiers
- Network configuration
- Performance metrics
- Operational status

Ensure this client is only used in trusted environments and consider the security implications of exposing this data.
