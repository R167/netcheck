package mcp

import (
	"github.com/R167/netcheck/checkers/api"
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
func configFromInput(name string, defaults checker.CheckerConfig, input ToolInput) checker.CheckerConfig {
	switch name {
	case "web":
		cfg := defaults.(web.WebConfig)
		if input.CheckDefaultCreds {
			cfg.CheckDefaultCreds = true
		}
		return cfg

	case "ports":
		cfg := defaults.(ports.PortsConfig)
		if len(input.Ports) > 0 {
			cfg.Ports = input.Ports
		}
		return cfg

	case "upnp":
		cfg := defaults.(upnp.UPnPConfig)
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
		cfg := defaults.(mdns.MDNSConfig)
		if input.Detailed {
			cfg.Detailed = true
		}
		return cfg

	case "ssdp":
		cfg := defaults.(ssdp.SSDPConfig)
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
		cfg := defaults.(ipv6.IPv6Config)
		if input.ShowVirtual {
			cfg.ShowVirtual = true
		}
		return cfg

	case "device":
		cfg := defaults.(device.DeviceConfig)
		if input.ShowVirtual {
			cfg.ShowVirtual = true
		}
		return cfg

	case "external":
		cfg := defaults.(external.ExternalConfig)
		if input.TestProxy {
			cfg.TestProxy = true
		}
		return cfg

	// Checkers with empty configs: natpmp, api, starlink, routes, lldp
	case "api":
		return defaults.(api.APIConfig)

	default:
		return defaults
	}
}
