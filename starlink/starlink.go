package starlink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// Standard Starlink Dishy IP and port
	DefaultStarlinkIP   = "192.168.100.1"
	DefaultStarlinkPort = 9200

	// Alternative endpoints for testing
	LocalhostTestIP   = "127.0.0.1"
	LocalhostTestPort = 9200

	// Timeouts
	DialTimeout    = 5 * time.Second
	RequestTimeout = 10 * time.Second
)

// CheckStarlink attempts to detect and analyze a Starlink Dishy on the network
func CheckStarlink() *StarLinkInfo {
	info := &StarLinkInfo{
		Accessible:     false,
		SecurityIssues: make([]SecurityIssue, 0),
	}

	// Try different potential endpoints
	endpoints := []string{
		fmt.Sprintf("%s:%d", DefaultStarlinkIP, DefaultStarlinkPort),
		fmt.Sprintf("%s:%d", LocalhostTestIP, LocalhostTestPort),
	}

	var workingEndpoint string
	for _, endpoint := range endpoints {
		if isStarlinkAccessible(endpoint) {
			workingEndpoint = endpoint
			info.Accessible = true
			break
		}
	}

	if !info.Accessible {
		return info
	}

	// Gather device information
	if deviceInfo := getDeviceInfo(workingEndpoint); deviceInfo != nil {
		info.DeviceInfo = deviceInfo
	}

	// Gather status information
	if status := getStatus(workingEndpoint); status != nil {
		info.Status = status
	}

	// Gather configuration
	if config := getConfig(workingEndpoint); config != nil {
		info.Config = config
	}

	// Perform security assessment
	info.SecurityIssues = assessSecurity(info, workingEndpoint)

	return info
}

// isStarlinkAccessible checks if a Starlink gRPC service is accessible at the given endpoint
func isStarlinkAccessible(endpoint string) bool {
	// Try to establish a connection to the endpoint
	conn, err := net.DialTimeout("tcp", endpoint, DialTimeout)
	if err != nil {
		return false
	}
	conn.Close()

	// Try a basic gRPC call to verify it's actually Starlink
	cmd := exec.Command("grpcurl", "-plaintext", "-max-time", "5",
		"-d", `{"get_device_info":{}}`,
		endpoint, "SpaceX.API.Device.Device/Handle")

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check if the response looks like a Starlink response
	return strings.Contains(string(output), "deviceInfo") || strings.Contains(string(output), "apiVersion")
}

// getDeviceInfo retrieves device information from Starlink
func getDeviceInfo(endpoint string) *DeviceInfo {
	cmd := exec.Command("grpcurl", "-plaintext", "-max-time", "5",
		"-d", `{"get_device_info":{}}`,
		endpoint, "SpaceX.API.Device.Device/Handle")

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var resp GRPCResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil
	}

	if resp.GetDeviceInfo == nil {
		return nil
	}

	return &DeviceInfo{
		ID:              resp.GetDeviceInfo.DeviceInfo.ID,
		HardwareVersion: resp.GetDeviceInfo.DeviceInfo.HardwareVersion,
		SoftwareVersion: resp.GetDeviceInfo.DeviceInfo.SoftwareVersion,
		CountryCode:     resp.GetDeviceInfo.DeviceInfo.CountryCode,
		BootCount:       resp.GetDeviceInfo.DeviceInfo.BootCount,
		BuildID:         resp.GetDeviceInfo.DeviceInfo.BuildID,
	}
}

// getStatus retrieves operational status from Starlink
func getStatus(endpoint string) *DishStatus {
	cmd := exec.Command("grpcurl", "-plaintext", "-max-time", "5",
		"-d", `{"get_status":{}}`,
		endpoint, "SpaceX.API.Device.Device/Handle")

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var resp GRPCResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil
	}

	if resp.DishGetStatus == nil {
		return nil
	}

	status := resp.DishGetStatus

	// Parse uptime from string to int64
	uptimeS, _ := strconv.ParseInt(status.DeviceState.UptimeS, 10, 64)

	return &DishStatus{
		UptimeS:               uptimeS,
		DownlinkThroughputBps: status.DownlinkThroughputBps,
		UplinkThroughputBps:   status.UplinkThroughputBps,
		PopPingLatencyMs:      status.PopPingLatencyMs,
		BoresightAzimuthDeg:   status.BoresightAzimuthDeg,
		BoresightElevationDeg: status.BoresightElevationDeg,
		EthSpeedMbps:          status.EthSpeedMbps,
		ConnectedRouters:      status.ConnectedRouters,
		HasActuators:          status.HasActuators,
		DisablementCode:       status.DisablementCode,
		SoftwareUpdateState:   status.SoftwareUpdateState,
	}
}

// getConfig retrieves configuration from Starlink
func getConfig(endpoint string) *DishConfig {
	cmd := exec.Command("grpcurl", "-plaintext", "-max-time", "5",
		"-d", `{"dish_get_config":{}}`,
		endpoint, "SpaceX.API.Device.Device/Handle")

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var resp GRPCResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil
	}

	if resp.DishGetConfig == nil {
		return nil
	}

	config := resp.DishGetConfig.DishConfig

	return &DishConfig{
		SwupdateRebootHour:                   config.SwupdateRebootHour,
		ApplySnowMeltMode:                    config.ApplySnowMeltMode,
		ApplyLocationRequestMode:             config.ApplyLocationRequestMode,
		ApplyLevelDishMode:                   config.ApplyLevelDishMode,
		ApplyPowerSaveStartMinutes:           config.ApplyPowerSaveStartMinutes,
		ApplyPowerSaveDurationMinutes:        config.ApplyPowerSaveDurationMinutes,
		ApplyPowerSaveMode:                   config.ApplyPowerSaveMode,
		ApplySwupdateThreeDayDeferralEnabled: config.ApplySwupdateThreeDayDeferralEnabled,
		ApplyAssetClass:                      config.ApplyAssetClass,
		ApplySwupdateRebootHour:              config.ApplySwupdateRebootHour,
	}
}

// FormatStarlinkReport generates a human-readable report of Starlink findings
func FormatStarlinkReport(info *StarLinkInfo) string {
	if info == nil || !info.Accessible {
		return ""
	}

	var report bytes.Buffer

	report.WriteString("\n🛰️  Starlink Dishy Analysis\n")
	report.WriteString("===========================\n")

	if info.DeviceInfo != nil {
		report.WriteString(fmt.Sprintf("📡 Device ID: %s\n", info.DeviceInfo.ID))
		report.WriteString(fmt.Sprintf("🔧 Hardware: %s\n", info.DeviceInfo.HardwareVersion))
		report.WriteString(fmt.Sprintf("💾 Software: %s\n", info.DeviceInfo.SoftwareVersion))
		report.WriteString(fmt.Sprintf("🌍 Country: %s\n", info.DeviceInfo.CountryCode))
		report.WriteString(fmt.Sprintf("🔄 Boot Count: %d\n", info.DeviceInfo.BootCount))
	}

	if info.Status != nil {
		uptimeDays := info.Status.UptimeS / (24 * 3600)
		uptimeHours := (info.Status.UptimeS % (24 * 3600)) / 3600
		report.WriteString(fmt.Sprintf("⏱️  Uptime: %dd %dh\n", uptimeDays, uptimeHours))
		report.WriteString(fmt.Sprintf("📶 Signal: %.1f°az %.1f°el\n",
			info.Status.BoresightAzimuthDeg, info.Status.BoresightElevationDeg))
		report.WriteString(fmt.Sprintf("⬇️  Download: %.1f Mbps\n", info.Status.DownlinkThroughputBps/1000000))
		report.WriteString(fmt.Sprintf("⬆️  Upload: %.1f Mbps\n", info.Status.UplinkThroughputBps/1000000))
		report.WriteString(fmt.Sprintf("🏓 Latency: %.1f ms\n", info.Status.PopPingLatencyMs))
		report.WriteString(fmt.Sprintf("🔌 Ethernet: %d Mbps\n", info.Status.EthSpeedMbps))
		report.WriteString(fmt.Sprintf("🚫 Status: %s\n", info.Status.DisablementCode))

		if len(info.Status.ConnectedRouters) > 0 {
			report.WriteString(fmt.Sprintf("🌐 Routers: %d connected\n", len(info.Status.ConnectedRouters)))
			for _, router := range info.Status.ConnectedRouters {
				report.WriteString(fmt.Sprintf("  - %s\n", router))
			}
		}
	}

	if len(info.SecurityIssues) > 0 {
		report.WriteString("\n🚨 Security Issues:\n")
		for i, issue := range info.SecurityIssues {
			severityIcon := getSeverityIcon(issue.Severity)
			report.WriteString(fmt.Sprintf("%d. %s [%s] %s\n",
				i+1, severityIcon, issue.Severity, issue.Title))
			report.WriteString(fmt.Sprintf("   %s\n", issue.Description))
			if issue.Remediation != "" {
				report.WriteString(fmt.Sprintf("   💡 %s\n", issue.Remediation))
			}
		}
	}

	return report.String()
}

// getSeverityIcon returns an appropriate icon for the security issue severity
func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🚨"
	case "HIGH":
		return "⚠️"
	case "MEDIUM":
		return "🔶"
	case "LOW":
		return "ℹ️"
	default:
		return "❓"
	}
}