package mcp

import (
	"github.com/R167/netcheck/checkers/device"
	"github.com/R167/netcheck/checkers/external"
	"github.com/R167/netcheck/checkers/ipv6"
	"github.com/R167/netcheck/checkers/mdns"
	"github.com/R167/netcheck/checkers/ports"
	"github.com/R167/netcheck/checkers/ssdp"
	"github.com/R167/netcheck/checkers/upnp"
	"github.com/R167/netcheck/checkers/web"
	"github.com/R167/netcheck/internal/checker"
)

// configFromInput builds a checker-specific config by merging the MCP ToolInput
// fields with the checker's defaults. Fields that are zero-valued in the input
// keep their default values.
//
// Note: Because ToolInput uses `omitempty` booleans, callers cannot distinguish
// "not provided" from "false". This means booleans that default to true in a
// checker's config cannot be disabled via MCP. This is a known limitation of
// the flat ToolInput design.
func configFromInput(name string, defaults checker.CheckerConfig, input ToolInput) checker.CheckerConfig {
	switch name {
	case "web":
		cfg, ok := defaults.(web.WebConfig)
		if !ok {
			return defaults
		}
		if input.CheckDefaultCreds {
			cfg.CheckDefaultCreds = true
		}
		return cfg

	case "ports":
		cfg, ok := defaults.(ports.PortsConfig)
		if !ok {
			return defaults
		}
		if len(input.Ports) > 0 {
			cfg.Ports = input.Ports
		}
		return cfg

	case "upnp":
		cfg, ok := defaults.(upnp.UPnPConfig)
		if !ok {
			return defaults
		}
		if input.EnumerateMappings {
			cfg.EnumerateMappings = true
		}
		if input.CheckIPv6Firewall {
			cfg.CheckIPv6Firewall = true
		}
		if input.EnumerateServices {
			cfg.EnumerateServices = true
		}
		if input.CheckSecurityIssues {
			cfg.CheckSecurityIssues = true
		}
		return cfg

	case "mdns":
		cfg, ok := defaults.(mdns.MDNSConfig)
		if !ok {
			return defaults
		}
		if input.Detailed {
			cfg.Detailed = true
		}
		return cfg

	case "ssdp":
		cfg, ok := defaults.(ssdp.SSDPConfig)
		if !ok {
			return defaults
		}
		if input.IPv4Enabled {
			cfg.IPv4Enabled = true
		}
		if input.IPv6Enabled {
			cfg.IPv6Enabled = true
		}
		if len(input.SearchTargets) > 0 {
			cfg.SearchTargets = input.SearchTargets
		}
		return cfg

	case "ipv6":
		cfg, ok := defaults.(ipv6.IPv6Config)
		if !ok {
			return defaults
		}
		if input.ShowVirtual {
			cfg.ShowVirtual = true
		}
		return cfg

	case "device":
		cfg, ok := defaults.(device.DeviceConfig)
		if !ok {
			return defaults
		}
		if input.ShowVirtual {
			cfg.ShowVirtual = true
		}
		return cfg

	case "external":
		cfg, ok := defaults.(external.ExternalConfig)
		if !ok {
			return defaults
		}
		if input.TestProxy {
			cfg.TestProxy = true
		}
		return cfg

	default:
		return defaults
	}
}
