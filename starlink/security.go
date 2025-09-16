package starlink

import (
	"fmt"
	"strings"
)

// assessSecurity performs security analysis on Starlink configuration and status
func assessSecurity(info *StarLinkInfo, endpoint string) []SecurityIssue {
	var issues []SecurityIssue

	// Check if Starlink gRPC is accessible from LAN
	issues = append(issues, checkGRPCExposure(endpoint)...)

	// Analyze device configuration for security issues
	if info.DeviceInfo != nil {
		issues = append(issues, checkDeviceSecurity(info.DeviceInfo)...)
	}

	if info.Status != nil {
		issues = append(issues, checkStatusSecurity(info.Status)...)
	}

	if info.Config != nil {
		issues = append(issues, checkConfigSecurity(info.Config)...)
	}

	return issues
}

// checkGRPCExposure analyzes the exposure of Starlink gRPC interface
func checkGRPCExposure(endpoint string) []SecurityIssue {
	var issues []SecurityIssue

	// Always flag gRPC exposure as it provides extensive system information
	issues = append(issues, SecurityIssue{
		Severity:    "MEDIUM",
		Category:    "Information Disclosure",
		Title:       "Starlink gRPC API exposed to LAN",
		Description: fmt.Sprintf("Starlink Dishy gRPC API is accessible from %s", endpoint),
		Impact:      "Exposes detailed device information, network topology, performance metrics, and configuration details to any device on the local network",
		Remediation: "This is normal Starlink behavior. Ensure your local network is properly secured and monitor for unauthorized access",
	})

	// Check if it's accessible from non-standard endpoint (potential port forwarding)
	if strings.Contains(endpoint, "127.0.0.1") || strings.Contains(endpoint, "localhost") {
		issues = append(issues, SecurityIssue{
			Severity:    "HIGH",
			Category:    "Network Exposure",
			Title:       "Starlink API accessible via localhost port forwarding",
			Description: "Starlink gRPC API appears to be port-forwarded to localhost, potentially exposing it beyond the local network",
			Impact:      "May allow remote access to sensitive Starlink configuration and status information",
			Remediation: "Review port forwarding configuration and ensure it's only accessible from intended sources",
		})
	}

	return issues
}

// checkDeviceSecurity analyzes device information for security concerns
func checkDeviceSecurity(device *DeviceInfo) []SecurityIssue {
	var issues []SecurityIssue

	// Check for old firmware versions (this would need to be updated with known vulnerable versions)
	if strings.Contains(device.SoftwareVersion, "2024.") {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Category:    "Outdated Software",
			Title:       "Potentially outdated Starlink firmware",
			Description: fmt.Sprintf("Device is running firmware version %s which may be outdated", device.SoftwareVersion),
			Impact:      "Outdated firmware may contain known security vulnerabilities",
			Remediation: "Check for and install the latest Starlink firmware updates through the official app",
		})
	}

	// High boot count could indicate instability or frequent power cycles
	if device.BootCount > 500 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Device Health",
			Title:       "High boot count detected",
			Description: fmt.Sprintf("Device has rebooted %d times, which is unusually high", device.BootCount),
			Impact:      "Frequent reboots may indicate hardware issues or environmental problems affecting security",
			Remediation: "Investigate power stability and environmental conditions. Consider contacting Starlink support if issues persist",
		})
	}

	// Flag if device ID is exposed (which it always is via gRPC)
	issues = append(issues, SecurityIssue{
		Severity:    "LOW",
		Category:    "Information Disclosure",
		Title:       "Device identifier disclosed via API",
		Description: fmt.Sprintf("Device ID %s is accessible without authentication", device.ID),
		Impact:      "Device identifiers can be used for tracking and potentially targeted attacks",
		Remediation: "This is inherent to Starlink's design. Monitor network access and ensure proper network segmentation",
	})

	return issues
}

// checkStatusSecurity analyzes operational status for security implications
func checkStatusSecurity(status *DishStatus) []SecurityIssue {
	var issues []SecurityIssue

	// Check disablement code for security-related issues
	if status.DisablementCode != "OKAY" {
		severity := "MEDIUM"
		if strings.Contains(status.DisablementCode, "THERMAL") || strings.Contains(status.DisablementCode, "OBSTRUCT") {
			severity = "LOW"
		}

		issues = append(issues, SecurityIssue{
			Severity:    severity,
			Category:    "Device Status",
			Title:       "Starlink service issue detected",
			Description: fmt.Sprintf("Device status shows: %s", status.DisablementCode),
			Impact:      "Service disruptions may affect network connectivity and security monitoring",
			Remediation: "Address the indicated issue through the Starlink app or by contacting support",
		})
	}

	// Flag if connected to multiple routers (potential network complexity)
	if len(status.ConnectedRouters) > 1 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Network Topology",
			Title:       "Multiple router connections detected",
			Description: fmt.Sprintf("Starlink is connected to %d routers: %v", len(status.ConnectedRouters), status.ConnectedRouters),
			Impact:      "Complex network topology may create security blind spots or routing issues",
			Remediation: "Review network configuration to ensure proper segmentation and security controls",
		})
	}

	// Check for unusually low performance (could indicate issues)
	if status.DownlinkThroughputBps < 10000000 { // Less than 10 Mbps
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Performance",
			Title:       "Low downlink performance detected",
			Description: fmt.Sprintf("Current downlink speed is %.1f Mbps, which is unusually low", status.DownlinkThroughputBps/1000000),
			Impact:      "Poor performance may indicate obstructions, interference, or potential attacks",
			Remediation: "Check for obstructions, verify optimal dish positioning, and monitor for interference",
		})
	}

	// High latency could indicate routing issues
	if status.PopPingLatencyMs > 100 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Performance",
			Title:       "High latency detected",
			Description: fmt.Sprintf("Current latency is %.1f ms, which is higher than optimal", status.PopPingLatencyMs),
			Impact:      "High latency may indicate routing issues or potential network interference",
			Remediation: "Monitor network conditions and check for sources of interference",
		})
	}

	return issues
}

// checkConfigSecurity analyzes configuration for security implications
func checkConfigSecurity(config *DishConfig) []SecurityIssue {
	var issues []SecurityIssue

	// Check for potentially insecure update scheduling
	if config.SwupdateRebootHour < 2 || config.SwupdateRebootHour > 5 {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Update Policy",
			Title:       "Non-optimal update reboot schedule",
			Description: fmt.Sprintf("Software updates are scheduled to reboot at %d:00, which may not be optimal", config.SwupdateRebootHour),
			Impact:      "Updates during business hours may cause unexpected service interruptions",
			Remediation: "Consider scheduling updates during off-peak hours (2 AM - 5 AM) through the Starlink app",
		})
	}

	// Check if three-day deferral is disabled (could lead to forced updates)
	if !config.ApplySwupdateThreeDayDeferralEnabled {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Update Policy",
			Title:       "Update deferral disabled",
			Description: "Three-day update deferral is disabled, forcing immediate updates",
			Impact:      "Immediate updates may cause unexpected service interruptions and prevent testing",
			Remediation: "Consider enabling update deferral to allow for planned maintenance windows",
		})
	}

	// Check power saving configuration
	if !config.ApplyPowerSaveMode {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Category:    "Power Management",
			Title:       "Power save mode disabled",
			Description: "Power save mode is disabled, potentially increasing power consumption",
			Impact:      "Higher power consumption may affect operational costs and environmental impact",
			Remediation: "Consider enabling power save mode if compatible with usage patterns",
		})
	}

	return issues
}