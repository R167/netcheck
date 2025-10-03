package starlink

import (
	"bytes"
	"fmt"
	"time"

	"github.com/R167/netcheck/internal/output"
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
func CheckStarlink(out output.Output) *StarLinkInfo {
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
	var client *Client

	for _, endpoint := range endpoints {
		out.Debug("Trying Starlink endpoint: %s", endpoint)
		c, err := NewClient(endpoint, out)
		if err != nil {
			out.Debug("Failed to create client for %s: %v", endpoint, err)
			continue
		}

		// Test the connection by trying to get device info
		if c.IsAccessible() {
			out.Debug("Successfully connected to Starlink at %s", endpoint)
			workingEndpoint = endpoint
			client = c
			info.Accessible = true
			break
		}
		out.Debug("Endpoint %s not accessible", endpoint)
		c.Close()
	}

	if !info.Accessible || client == nil {
		out.Debug("No accessible Starlink endpoint found")
		return info
	}
	defer client.Close()

	// Gather device information
	out.Debug("Gathering device information...")
	deviceInfo, err := client.GetDeviceInfo()
	if err != nil {
		out.Debug("Failed to get device info: %v", err)
	} else {
		info.DeviceInfo = deviceInfo
		out.Debug("Device info retrieved successfully")
	}

	// Gather status information
	out.Debug("Gathering status information...")
	status, err := client.GetStatus()
	if err != nil {
		out.Debug("Failed to get status: %v", err)
	} else {
		info.Status = status
	}

	// Gather configuration
	out.Debug("Gathering configuration...")
	config, err := client.GetConfig()
	if err != nil {
		out.Debug("Failed to get config: %v", err)
	} else {
		info.Config = config
	}

	// Perform security assessment
	info.SecurityIssues = assessSecurity(info, workingEndpoint)

	return info
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
