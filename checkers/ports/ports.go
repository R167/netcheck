package ports

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
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

func (c *PortsChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	cfg := config.(PortsConfig)
	scanCommonPorts(router, cfg)
}

func (c *PortsChecker) RunStandalone(config checker.CheckerConfig) {
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

func scanCommonPorts(router *common.RouterInfo, cfg PortsConfig) {
	fmt.Println("\n🔍 Scanning common management ports...")

	for _, port := range cfg.Ports {
		if isPortOpen(router.IP, port, cfg.PortTimeout) {
			router.OpenPorts = append(router.OpenPorts, port)
			fmt.Printf("  ✅ Port %d open\n", port)

			if issue, exists := managementPorts[port]; exists {
				router.Issues = append(router.Issues, issue)
			}
		}
	}

	if len(router.OpenPorts) == 0 {
		fmt.Println("  ℹ️  No common management ports detected")
	}
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
