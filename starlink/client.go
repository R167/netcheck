package starlink

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
)

// Client provides access to Starlink API
type Client struct {
	endpoint string
}

// NewClient creates a new Starlink client
func NewClient(endpoint string) (*Client, error) {
	// Test connectivity first
	conn, err := net.DialTimeout("tcp", endpoint, DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}
	conn.Close()

	return &Client{endpoint: endpoint}, nil
}

// IsAccessible checks if the Starlink service is accessible
func (c *Client) IsAccessible() bool {
	_, err := c.GetDeviceInfo()
	return err == nil
}

// GetDeviceInfo retrieves device information
func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

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

// GetStatus retrieves status information (simplified for now)
func (c *Client) GetStatus() (*DishStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "grpcurl", "-plaintext", "-max-time", "8",
		"-d", `{"get_status":{}}`,
		c.endpoint, "SpaceX.API.Device.Device/Handle")

	_, err := cmd.Output()
	if err != nil {
		// Return empty status if call fails rather than error
		return &DishStatus{}, nil
	}

	// For now, return a basic status structure
	// TODO: Parse actual status response
	return &DishStatus{}, nil
}

// GetConfig retrieves configuration (simplified for now)
func (c *Client) GetConfig() (*DishConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "grpcurl", "-plaintext", "-max-time", "8",
		"-d", `{"dish_get_config":{}}`,
		c.endpoint, "SpaceX.API.Device.Device/Handle")

	_, err := cmd.Output()
	if err != nil {
		// Return empty config if call fails rather than error
		return &DishConfig{}, nil
	}

	// For now, return a basic config structure
	// TODO: Parse actual config response
	return &DishConfig{}, nil
}

// Close is a no-op for this client type
func (c *Client) Close() error {
	return nil
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
