package starlink

import (
	"reflect"
	"testing"
)

func TestParseDeviceInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected *DeviceInfo
	}{
		{
			name: "complete device info",
			input: map[string]interface{}{
				"id":              "ut01234567-89ab-cdef-0123-456789abcdef",
				"hardwareVersion": "rev3_proto2",
				"softwareVersion": "2024.01.01.mr12345",
				"countryCode":     "US",
				"bootcount":       float64(42),
				"buildId":         "build-12345",
			},
			expected: &DeviceInfo{
				ID:              "ut01234567-89ab-cdef-0123-456789abcdef",
				HardwareVersion: "rev3_proto2",
				SoftwareVersion: "2024.01.01.mr12345",
				CountryCode:     "US",
				BootCount:       42,
				BuildID:         "build-12345",
			},
		},
		{
			name: "partial device info",
			input: map[string]interface{}{
				"id":              "partial-id",
				"hardwareVersion": "rev1",
			},
			expected: &DeviceInfo{
				ID:              "partial-id",
				HardwareVersion: "rev1",
			},
		},
		{
			name:     "empty device info",
			input:    map[string]interface{}{},
			expected: &DeviceInfo{},
		},
		{
			name: "wrong types ignored",
			input: map[string]interface{}{
				"id":        123, // wrong type, should be string
				"bootcount": "not a number",
			},
			expected: &DeviceInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDeviceInfo(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseDeviceInfo() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected *DishStatus
	}{
		{
			name: "complete status",
			input: map[string]interface{}{
				"deviceState": map[string]interface{}{
					"uptimeS": "86400",
				},
				"downlinkThroughputBps": float64(150000000),
				"uplinkThroughputBps":   float64(20000000),
				"popPingLatencyMs":      float64(25.5),
				"boresightAzimuthDeg":   float64(180.0),
				"boresightElevationDeg": float64(45.0),
				"ethSpeedMbps":          float64(1000),
				"connectedRouters":      []interface{}{"router1", "router2"},
				"hasActuators":          "true",
				"disablementCode":       "OKAY",
				"softwareUpdateState":   "IDLE",
			},
			expected: &DishStatus{
				UptimeS:               86400,
				DownlinkThroughputBps: 150000000,
				UplinkThroughputBps:   20000000,
				PopPingLatencyMs:      25.5,
				BoresightAzimuthDeg:   180.0,
				BoresightElevationDeg: 45.0,
				EthSpeedMbps:          1000,
				ConnectedRouters:      []string{"router1", "router2"},
				HasActuators:          "true",
				DisablementCode:       "OKAY",
				SoftwareUpdateState:   "IDLE",
			},
		},
		{
			name: "partial status",
			input: map[string]interface{}{
				"popPingLatencyMs": float64(30.0),
				"disablementCode":  "OKAY",
			},
			expected: &DishStatus{
				PopPingLatencyMs: 30.0,
				DisablementCode:  "OKAY",
			},
		},
		{
			name:     "empty status",
			input:    map[string]interface{}{},
			expected: &DishStatus{},
		},
		{
			name: "empty connected routers",
			input: map[string]interface{}{
				"connectedRouters": []interface{}{},
			},
			expected: &DishStatus{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStatus(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseStatus() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected *DishConfig
	}{
		{
			name: "complete config",
			input: map[string]interface{}{
				"swupdateRebootHour":                   float64(3),
				"applySnowMeltMode":                    true,
				"applyLocationRequestMode":             false,
				"applyLevelDishMode":                   true,
				"applyPowerSaveStartMinutes":           false,
				"applyPowerSaveDurationMinutes":        false,
				"applyPowerSaveMode":                   true,
				"applySwupdateThreeDayDeferralEnabled": true,
				"applyAssetClass":                      false,
				"applySwupdateRebootHour":              true,
			},
			expected: &DishConfig{
				SwupdateRebootHour:                   3,
				ApplySnowMeltMode:                    true,
				ApplyLocationRequestMode:             false,
				ApplyLevelDishMode:                   true,
				ApplyPowerSaveStartMinutes:           false,
				ApplyPowerSaveDurationMinutes:        false,
				ApplyPowerSaveMode:                   true,
				ApplySwupdateThreeDayDeferralEnabled: true,
				ApplyAssetClass:                      false,
				ApplySwupdateRebootHour:              true,
			},
		},
		{
			name: "partial config",
			input: map[string]interface{}{
				"swupdateRebootHour": float64(5),
				"applySnowMeltMode":  true,
			},
			expected: &DishConfig{
				SwupdateRebootHour: 5,
				ApplySnowMeltMode:  true,
			},
		},
		{
			name:     "empty config",
			input:    map[string]interface{}{},
			expected: &DishConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseConfig(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseConfig() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestFormatStarlinkReport(t *testing.T) {
	tests := []struct {
		name        string
		info        *StarLinkInfo
		shouldBeNil bool
		contains    []string
	}{
		{
			name:        "nil info",
			info:        nil,
			shouldBeNil: true,
		},
		{
			name: "not accessible",
			info: &StarLinkInfo{
				Accessible: false,
			},
			shouldBeNil: true,
		},
		{
			name: "basic info",
			info: &StarLinkInfo{
				Accessible: true,
				DeviceInfo: &DeviceInfo{
					ID:              "test-id",
					HardwareVersion: "rev3",
					SoftwareVersion: "2024.01.01",
					CountryCode:     "US",
					BootCount:       10,
				},
			},
			contains: []string{
				"Starlink Dishy Analysis",
				"test-id",
				"rev3",
				"2024.01.01",
				"US",
			},
		},
		{
			name: "with status",
			info: &StarLinkInfo{
				Accessible: true,
				Status: &DishStatus{
					UptimeS:          86400,
					PopPingLatencyMs: 25.5,
					EthSpeedMbps:     1000,
				},
			},
			contains: []string{
				"Uptime: 1d 0h",
				"25.5 ms",
				"1000 Mbps",
			},
		},
		{
			name: "with security issues",
			info: &StarLinkInfo{
				Accessible: true,
				SecurityIssues: []SecurityIssue{
					{
						Severity:    "HIGH",
						Title:       "Test Issue",
						Description: "Test Description",
						Remediation: "Test Fix",
					},
				},
			},
			contains: []string{
				"Security Issues",
				"Test Issue",
				"Test Description",
				"Test Fix",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatStarlinkReport(tt.info)
			if tt.shouldBeNil {
				if result != "" {
					t.Errorf("FormatStarlinkReport() = %q, want empty string", result)
				}
				return
			}
			for _, s := range tt.contains {
				if !containsString(result, s) {
					t.Errorf("FormatStarlinkReport() should contain %q", s)
				}
			}
		})
	}
}

func TestGetSeverityIcon(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "🚨"},
		{"HIGH", "⚠️"},
		{"MEDIUM", "🔶"},
		{"LOW", "ℹ️"},
		{"UNKNOWN", "❓"},
		{"", "❓"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := getSeverityIcon(tt.severity)
			if result != tt.expected {
				t.Errorf("getSeverityIcon(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
