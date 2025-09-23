package starlink

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
)

// Client provides access to Starlink API using grpcurl library
type Client struct {
	endpoint string
}

// NewClient creates a new Starlink client
func NewClient(endpoint string) (*Client, error) {
	// Test connectivity first
	tcpConn, err := net.DialTimeout("tcp", endpoint, DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}
	tcpConn.Close()

	return &Client{endpoint: endpoint}, nil
}

// Close is a no-op for the grpcurl library client
func (c *Client) Close() error {
	return nil
}

// IsAccessible checks if the Starlink service is accessible
func (c *Client) IsAccessible() bool {
	_, err := c.GetDeviceInfo()
	return err == nil
}

// GetDeviceInfo retrieves device information using grpcurl (improved version)
func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	// Use grpcurl command but with proper timeout handling and error recovery
	cmd := exec.CommandContext(ctx, "grpcurl", "-plaintext", "-max-time", "8",
		"-d", `{"get_device_info":{}}`,
		c.endpoint, "SpaceX.API.Device.Device/Handle")

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("grpcurl failed: %w", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse device info from response
	if getDeviceInfo, ok := response["getDeviceInfo"].(map[string]interface{}); ok {
		if deviceInfo, ok := getDeviceInfo["deviceInfo"].(map[string]interface{}); ok {
			return parseDeviceInfo(deviceInfo), nil
		}
	}

	return nil, fmt.Errorf("invalid response format")
}

// GetStatus retrieves status information
func (c *Client) GetStatus() (*DishStatus, error) {
	// Return empty status for now - could implement similar to GetDeviceInfo
	return &DishStatus{}, nil
}

// GetConfig retrieves configuration
func (c *Client) GetConfig() (*DishConfig, error) {
	// Return empty config for now - could implement similar to GetDeviceInfo
	return &DishConfig{}, nil
}

// parseDeviceInfo parses device info from API response
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
