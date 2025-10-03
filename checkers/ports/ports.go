package ports

import (
	"net"
	"strconv"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type PortsChecker struct{}

type PortsConfig struct {
	Ports       []int
	PortTimeout time.Duration
}

var managementPorts = map[int]common.SecurityIssue{
	22: {
		Severity:    common.SeverityMedium,
		Description: "SSH service exposed",
		Details:     "SSH is accessible from the network. Ensure strong authentication is configured.",
	},
	23: {
		Severity:    common.SeverityHigh,
		Description: "Telnet service exposed",
		Details:     "Telnet transmits data in plain text. Consider disabling if not needed.",
	},
	161: {
		Severity:    common.SeverityMedium,
		Description: "SNMP service exposed",
		Details:     "SNMP can expose device information. Ensure community strings are changed from defaults.",
	},
}

func NewPortsChecker() checker.Checker {
	return &PortsChecker{}
}

func (c *PortsChecker) Name() string {
	return "ports"
}

func (c *PortsChecker) Description() string {
	return "Common management ports"
}

func (c *PortsChecker) Icon() string {
	return "🔍"
}

func (c *PortsChecker) DefaultConfig() checker.CheckerConfig {
	return PortsConfig{
		Ports:       []int{22, 23, 80, 443, 8080, 8443, 21, 53, 161, 8291},
		PortTimeout: common.PortTimeout,
	}
}

func (c *PortsChecker) RequiresRouter() bool {
	return true
}

func (c *PortsChecker) DefaultEnabled() bool {
	return true
}

func (c *PortsChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyGateway, checker.DependencyRouterInfo}
}

func (c *PortsChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	cfg := config.(PortsConfig)
	scanCommonPorts(router, cfg, out)
}

func (c *PortsChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
}

func (c *PortsChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "scan_ports",
		Description: "Scan common management ports on a router",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
				"ports": map[string]interface{}{
					"type":        "array",
					"description": "List of ports to scan",
					"items": map[string]interface{}{
						"type": "integer",
					},
					"default": []int{22, 23, 80, 443, 8080, 8443, 21, 53, 161, 8291},
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func scanCommonPorts(router *common.RouterInfo, cfg PortsConfig, out output.Output) {
	out.Section("🔍", "Scanning common management ports...")
	out.Debug("Ports: Scanning %d ports on %s with timeout %v", len(cfg.Ports), router.IP, cfg.PortTimeout)

	for _, port := range cfg.Ports {
		out.Debug("Ports: Testing port %d", port)
		if isPortOpen(router.IP, port, cfg.PortTimeout, out) {
			router.OpenPorts = append(router.OpenPorts, port)
			out.Success("Port %d open", port)

			if issue, exists := managementPorts[port]; exists {
				router.Issues = append(router.Issues, issue)
				out.Debug("Ports: Port %d has security implications", port)
			}
		}
	}

	if len(router.OpenPorts) == 0 {
		out.Info("ℹ️  No common management ports detected")
	} else {
		out.Debug("Ports: Found %d open ports", len(router.OpenPorts))
	}
}

func isPortOpen(ip string, port int, timeout time.Duration, out output.Output) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		out.Debug("Ports: Port %d closed or filtered: %v", port, err)
		return false
	}
	conn.Close()
	out.Debug("Ports: Port %d is open", port)
	return true
}
