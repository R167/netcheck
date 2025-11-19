package starlink

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/R167/netcheck/internal/output"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Client provides access to Starlink API using native gRPC
type Client struct {
	endpoint   string
	conn       *grpc.ClientConn
	reflClient grpc_reflection_v1alpha.ServerReflectionClient
	out        output.Output

	// Cached service descriptor to avoid repeated reflection calls
	serviceDescMu sync.RWMutex
	serviceDesc   protoreflect.ServiceDescriptor
}

// NewClient creates a new Starlink client
func NewClient(endpoint string, out output.Output) (*Client, error) {
	out.Debug("Attempting to connect to Starlink at %s", endpoint)

	// Test connectivity first
	tcpConn, err := net.DialTimeout("tcp", endpoint, DialTimeout)
	if err != nil {
		out.Debug("TCP connection failed: %v", err)
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}
	tcpConn.Close()
	out.Debug("TCP connection successful")

	// Create gRPC connection
	out.Debug("Creating gRPC client connection")
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		out.Debug("gRPC client creation failed: %v", err)
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	client := &Client{
		endpoint:   endpoint,
		conn:       conn,
		reflClient: grpc_reflection_v1alpha.NewServerReflectionClient(conn),
		out:        out,
	}

	out.Debug("Starlink client created successfully")
	return client, nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsAccessible checks if the Starlink service is accessible
func (c *Client) IsAccessible() bool {
	_, err := c.GetDeviceInfo()
	return err == nil
}

// getServiceDescriptor returns a cached service descriptor or resolves it
func (c *Client) getServiceDescriptor(ctx context.Context) (protoreflect.ServiceDescriptor, error) {
	// Check cache first with read lock
	c.serviceDescMu.RLock()
	if c.serviceDesc != nil {
		desc := c.serviceDesc
		c.serviceDescMu.RUnlock()
		c.out.Debug("getServiceDescriptor: Using cached service descriptor")
		return desc, nil
	}
	c.serviceDescMu.RUnlock()

	// Resolve and cache with write lock
	c.serviceDescMu.Lock()
	defer c.serviceDescMu.Unlock()

	// Double-check after acquiring write lock
	if c.serviceDesc != nil {
		return c.serviceDesc, nil
	}

	desc, err := c.resolveService(ctx, "SpaceX.API.Device.Device")
	if err != nil {
		return nil, err
	}
	c.serviceDesc = desc
	return desc, nil
}

// GetDeviceInfo retrieves device information using native gRPC with reflection
func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	c.out.Debug("GetDeviceInfo: Starting device info retrieval")
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	// Get the service descriptor for SpaceX.API.Device.Device
	c.out.Debug("GetDeviceInfo: Resolving service descriptor")
	serviceDesc, err := c.getServiceDescriptor(ctx)
	if err != nil {
		c.out.Debug("GetDeviceInfo: Failed to resolve service: %v", err)
		return nil, fmt.Errorf("failed to resolve service: %w", err)
	}
	c.out.Debug("GetDeviceInfo: Service resolved successfully")

	// Find the Handle method
	c.out.Debug("GetDeviceInfo: Looking for Handle method")
	handleMethod := serviceDesc.Methods().ByName("Handle")
	if handleMethod == nil {
		c.out.Debug("GetDeviceInfo: Handle method not found")
		return nil, fmt.Errorf("Handle method not found")
	}
	c.out.Debug("GetDeviceInfo: Handle method found")

	// Get request and response message descriptors
	reqDesc := handleMethod.Input()
	respDesc := handleMethod.Output()
	c.out.Debug("GetDeviceInfo: Request type: %s, Response type: %s", reqDesc.FullName(), respDesc.FullName())

	// Create dynamic request message with get_device_info field
	req := dynamicpb.NewMessage(reqDesc)

	// Find the get_device_info field (should be field 1004 based on Starlink API)
	c.out.Debug("GetDeviceInfo: Looking for get_device_info field in request")
	getDeviceInfoField := reqDesc.Fields().ByName("get_device_info")
	if getDeviceInfoField == nil {
		c.out.Debug("GetDeviceInfo: get_device_info field not found, listing all fields:")
		for i := 0; i < reqDesc.Fields().Len(); i++ {
			field := reqDesc.Fields().Get(i)
			c.out.Debug("  Field %d: %s (number %d, type %s)", i, field.Name(), field.Number(), field.Kind())
		}
		return nil, fmt.Errorf("get_device_info field not found in request message")
	}
	c.out.Debug("GetDeviceInfo: get_device_info field found (field number %d)", getDeviceInfoField.Number())

	// Create an empty message for get_device_info
	getDeviceInfoMsg := dynamicpb.NewMessage(getDeviceInfoField.Message())
	req.Set(getDeviceInfoField, protoreflect.ValueOfMessage(getDeviceInfoMsg))
	c.out.Debug("GetDeviceInfo: Request message constructed")

	// Invoke the method
	c.out.Debug("GetDeviceInfo: Invoking gRPC method")
	resp := dynamicpb.NewMessage(respDesc)
	err = c.conn.Invoke(ctx, "/SpaceX.API.Device.Device/Handle", req, resp)
	if err != nil {
		c.out.Debug("GetDeviceInfo: gRPC invocation failed: %v", err)
		return nil, fmt.Errorf("gRPC invocation failed: %w", err)
	}
	c.out.Debug("GetDeviceInfo: gRPC invocation successful")

	// Parse the response
	c.out.Debug("GetDeviceInfo: Parsing response")
	result, err := c.parseDeviceInfoResponse(resp)
	if err != nil {
		c.out.Debug("GetDeviceInfo: Failed to parse response: %v", err)
		return nil, err
	}
	c.out.Debug("GetDeviceInfo: Successfully parsed device info")
	return result, nil
}

// GetStatus retrieves status information
func (c *Client) GetStatus() (*DishStatus, error) {
	c.out.Debug("GetStatus: Starting status retrieval")
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	serviceDesc, err := c.getServiceDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve service: %w", err)
	}

	handleMethod := serviceDesc.Methods().ByName("Handle")
	if handleMethod == nil {
		return nil, fmt.Errorf("Handle method not found")
	}

	reqDesc := handleMethod.Input()
	respDesc := handleMethod.Output()

	req := dynamicpb.NewMessage(reqDesc)

	// Find the get_status field
	getStatusField := reqDesc.Fields().ByName("get_status")
	if getStatusField == nil {
		c.out.Debug("GetStatus: get_status field not found")
		return nil, fmt.Errorf("get_status field not found in request message")
	}

	getStatusMsg := dynamicpb.NewMessage(getStatusField.Message())
	req.Set(getStatusField, protoreflect.ValueOfMessage(getStatusMsg))

	resp := dynamicpb.NewMessage(respDesc)
	err = c.conn.Invoke(ctx, "/SpaceX.API.Device.Device/Handle", req, resp)
	if err != nil {
		return nil, fmt.Errorf("gRPC invocation failed: %w", err)
	}

	return c.parseStatusResponse(resp)
}

// GetConfig retrieves configuration
func (c *Client) GetConfig() (*DishConfig, error) {
	c.out.Debug("GetConfig: Starting config retrieval")
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	serviceDesc, err := c.getServiceDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve service: %w", err)
	}

	handleMethod := serviceDesc.Methods().ByName("Handle")
	if handleMethod == nil {
		return nil, fmt.Errorf("Handle method not found")
	}

	reqDesc := handleMethod.Input()
	respDesc := handleMethod.Output()

	req := dynamicpb.NewMessage(reqDesc)

	// Find the dish_get_config field
	getConfigField := reqDesc.Fields().ByName("dish_get_config")
	if getConfigField == nil {
		c.out.Debug("GetConfig: dish_get_config field not found")
		return nil, fmt.Errorf("dish_get_config field not found in request message")
	}

	getConfigMsg := dynamicpb.NewMessage(getConfigField.Message())
	req.Set(getConfigField, protoreflect.ValueOfMessage(getConfigMsg))

	resp := dynamicpb.NewMessage(respDesc)
	err = c.conn.Invoke(ctx, "/SpaceX.API.Device.Device/Handle", req, resp)
	if err != nil {
		return nil, fmt.Errorf("gRPC invocation failed: %w", err)
	}

	return c.parseConfigResponse(resp)
}

// parseStatusResponse parses the status from the dynamic response message
func (c *Client) parseStatusResponse(resp protoreflect.Message) (*DishStatus, error) {
	jsonBytes, err := protojson.Marshal(resp.Interface())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response to JSON: %w", err)
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	// Try to extract status from the response
	if dishGetStatus, ok := rawResp["dishGetStatus"].(map[string]interface{}); ok {
		return parseStatus(dishGetStatus), nil
	}

	return nil, fmt.Errorf("status not found in response")
}

// parseStatus parses DishStatus from JSON map
func parseStatus(data map[string]interface{}) *DishStatus {
	result := &DishStatus{}

	if deviceState, ok := data["deviceState"].(map[string]interface{}); ok {
		if uptimeStr, ok := deviceState["uptimeS"].(string); ok {
			var uptime int64
			fmt.Sscanf(uptimeStr, "%d", &uptime)
			result.UptimeS = uptime
		}
	}

	if v, ok := data["downlinkThroughputBps"].(float64); ok {
		result.DownlinkThroughputBps = v
	}
	if v, ok := data["uplinkThroughputBps"].(float64); ok {
		result.UplinkThroughputBps = v
	}
	if v, ok := data["popPingLatencyMs"].(float64); ok {
		result.PopPingLatencyMs = v
	}
	if v, ok := data["boresightAzimuthDeg"].(float64); ok {
		result.BoresightAzimuthDeg = v
	}
	if v, ok := data["boresightElevationDeg"].(float64); ok {
		result.BoresightElevationDeg = v
	}
	if v, ok := data["ethSpeedMbps"].(float64); ok {
		result.EthSpeedMbps = int(v)
	}
	if routers, ok := data["connectedRouters"].([]interface{}); ok {
		for _, r := range routers {
			if s, ok := r.(string); ok {
				result.ConnectedRouters = append(result.ConnectedRouters, s)
			}
		}
	}
	if v, ok := data["hasActuators"].(string); ok {
		result.HasActuators = v
	}
	if v, ok := data["disablementCode"].(string); ok {
		result.DisablementCode = v
	}
	if v, ok := data["softwareUpdateState"].(string); ok {
		result.SoftwareUpdateState = v
	}

	return result
}

// parseConfigResponse parses the config from the dynamic response message
func (c *Client) parseConfigResponse(resp protoreflect.Message) (*DishConfig, error) {
	jsonBytes, err := protojson.Marshal(resp.Interface())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response to JSON: %w", err)
	}

	var rawResp map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to parse config response: %w", err)
	}

	// Try to extract config from the response
	if dishGetConfig, ok := rawResp["dishGetConfig"].(map[string]interface{}); ok {
		if dishConfig, ok := dishGetConfig["dishConfig"].(map[string]interface{}); ok {
			return parseConfig(dishConfig), nil
		}
	}

	return nil, fmt.Errorf("config not found in response")
}

// parseConfig parses DishConfig from JSON map
func parseConfig(data map[string]interface{}) *DishConfig {
	result := &DishConfig{}

	if v, ok := data["swupdateRebootHour"].(float64); ok {
		result.SwupdateRebootHour = int(v)
	}
	if v, ok := data["applySnowMeltMode"].(bool); ok {
		result.ApplySnowMeltMode = v
	}
	if v, ok := data["applyLocationRequestMode"].(bool); ok {
		result.ApplyLocationRequestMode = v
	}
	if v, ok := data["applyLevelDishMode"].(bool); ok {
		result.ApplyLevelDishMode = v
	}
	if v, ok := data["applyPowerSaveStartMinutes"].(bool); ok {
		result.ApplyPowerSaveStartMinutes = v
	}
	if v, ok := data["applyPowerSaveDurationMinutes"].(bool); ok {
		result.ApplyPowerSaveDurationMinutes = v
	}
	if v, ok := data["applyPowerSaveMode"].(bool); ok {
		result.ApplyPowerSaveMode = v
	}
	if v, ok := data["applySwupdateThreeDayDeferralEnabled"].(bool); ok {
		result.ApplySwupdateThreeDayDeferralEnabled = v
	}
	if v, ok := data["applyAssetClass"].(bool); ok {
		result.ApplyAssetClass = v
	}
	if v, ok := data["applySwupdateRebootHour"].(bool); ok {
		result.ApplySwupdateRebootHour = v
	}

	return result
}

// resolveService uses gRPC reflection to get the service descriptor
func (c *Client) resolveService(ctx context.Context, serviceName string) (protoreflect.ServiceDescriptor, error) {
	c.out.Debug("resolveService: Requesting service %s", serviceName)
	stream, err := c.reflClient.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection stream: %w", err)
	}
	defer stream.CloseSend()

	// Request the file descriptor for the service
	err = stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send reflection request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive reflection response: %w", err)
	}

	fdResp, ok := resp.MessageResponse.(*grpc_reflection_v1alpha.ServerReflectionResponse_FileDescriptorResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected reflection response type")
	}

	// Parse file descriptors
	var fileProtos []*descriptorpb.FileDescriptorProto
	for _, fdBytes := range fdResp.FileDescriptorResponse.FileDescriptorProto {
		fd := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(fdBytes, fd); err != nil {
			return nil, fmt.Errorf("failed to unmarshal file descriptor: %w", err)
		}
		fileProtos = append(fileProtos, fd)
		c.out.Debug("resolveService: Got file descriptor for %s", fd.GetName())
	}

	// Build file descriptor from proto - need to register all dependencies first
	if len(fileProtos) == 0 {
		return nil, fmt.Errorf("no file descriptors returned")
	}

	// Create a file registry to resolve dependencies
	c.out.Debug("resolveService: Building file descriptors with dependencies")
	fileDescs, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{
		File: fileProtos,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create file descriptors: %w", err)
	}

	// Find the main file (the one containing the service)
	var mainFileDesc protoreflect.FileDescriptor
	for _, fp := range fileProtos {
		fd, err := fileDescs.FindFileByPath(fp.GetName())
		if err != nil {
			continue
		}
		// Check if this file has the service
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			if string(svc.FullName()) == serviceName {
				c.out.Debug("resolveService: Found service in file %s", fp.GetName())
				mainFileDesc = fd
				break
			}
		}
		if mainFileDesc != nil {
			break
		}
	}

	if mainFileDesc == nil {
		return nil, fmt.Errorf("service %s not found in any file descriptor", serviceName)
	}

	// Find the service in the file
	services := mainFileDesc.Services()
	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		if string(svc.FullName()) == serviceName {
			c.out.Debug("resolveService: Service descriptor resolved successfully")
			return svc, nil
		}
	}

	return nil, fmt.Errorf("service %s not found in file descriptor", serviceName)
}

// parseDeviceInfoResponse parses the device info from the dynamic response message
func (c *Client) parseDeviceInfoResponse(resp protoreflect.Message) (*DeviceInfo, error) {
	// Convert to JSON for easier parsing
	jsonBytes, err := protojson.Marshal(resp.Interface())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response to JSON: %w", err)
	}

	// Parse the JSON structure
	var rawResp map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &rawResp); err != nil {
		// Try direct field access instead
		return c.parseDeviceInfoDirect(resp)
	}

	// Try to extract device info from the response
	if getDeviceInfo, ok := rawResp["getDeviceInfo"].(map[string]interface{}); ok {
		if deviceInfo, ok := getDeviceInfo["deviceInfo"].(map[string]interface{}); ok {
			return parseDeviceInfo(deviceInfo), nil
		}
	}

	// Fallback to direct field access
	return c.parseDeviceInfoDirect(resp)
}

// parseDeviceInfoDirect parses device info using direct protobuf field access
func (c *Client) parseDeviceInfoDirect(resp protoreflect.Message) (*DeviceInfo, error) {
	fields := resp.Descriptor().Fields()

	// Look for get_device_info field in response
	getDeviceInfoField := fields.ByName("dish_get_device_info")
	if getDeviceInfoField == nil {
		getDeviceInfoField = fields.ByName("get_device_info")
	}
	if getDeviceInfoField == nil {
		return nil, fmt.Errorf("device info field not found in response")
	}

	if !resp.Has(getDeviceInfoField) {
		return nil, fmt.Errorf("response does not contain device info")
	}

	getDeviceInfoMsg := resp.Get(getDeviceInfoField).Message()
	deviceInfoFields := getDeviceInfoMsg.Descriptor().Fields()

	// Look for the nested device_info field
	deviceInfoField := deviceInfoFields.ByName("device_info")
	if deviceInfoField == nil {
		return nil, fmt.Errorf("nested device_info field not found")
	}

	if !getDeviceInfoMsg.Has(deviceInfoField) {
		return nil, fmt.Errorf("response does not contain nested device info")
	}

	deviceInfoMsg := getDeviceInfoMsg.Get(deviceInfoField).Message()

	return parseDeviceInfoFromProto(deviceInfoMsg), nil
}

// parseDeviceInfoFromProto extracts DeviceInfo from a protobuf message
func parseDeviceInfoFromProto(msg protoreflect.Message) *DeviceInfo {
	result := &DeviceInfo{}
	fields := msg.Descriptor().Fields()

	if idField := fields.ByName("id"); idField != nil && msg.Has(idField) {
		result.ID = msg.Get(idField).String()
	}
	if hwField := fields.ByName("hardware_version"); hwField != nil && msg.Has(hwField) {
		result.HardwareVersion = msg.Get(hwField).String()
	}
	if swField := fields.ByName("software_version"); swField != nil && msg.Has(swField) {
		result.SoftwareVersion = msg.Get(swField).String()
	}
	if ccField := fields.ByName("country_code"); ccField != nil && msg.Has(ccField) {
		result.CountryCode = msg.Get(ccField).String()
	}
	if bcField := fields.ByName("bootcount"); bcField != nil && msg.Has(bcField) {
		result.BootCount = int(msg.Get(bcField).Int())
	}
	if bidField := fields.ByName("build_id"); bidField != nil && msg.Has(bidField) {
		result.BuildID = msg.Get(bidField).String()
	}

	return result
}

// parseDeviceInfo parses device info from API response (JSON format for compatibility)
func parseDeviceInfo(deviceInfo map[string]interface{}) *DeviceInfo {
	result := &DeviceInfo{}

	if id, ok := deviceInfo["id"].(string); ok {
		result.ID = id
	}
	if hw, ok := deviceInfo["hardwareVersion"].(string); ok {
		result.HardwareVersion = hw
	}
	if sw, ok := deviceInfo["softwareVersion"].(string); ok {
		result.SoftwareVersion = sw
	}
	if cc, ok := deviceInfo["countryCode"].(string); ok {
		result.CountryCode = cc
	}
	if bc, ok := deviceInfo["bootcount"].(float64); ok {
		result.BootCount = int(bc)
	}
	if bid, ok := deviceInfo["buildId"].(string); ok {
		result.BuildID = bid
	}

	return result
}
