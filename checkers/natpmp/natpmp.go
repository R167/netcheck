package natpmp

import (
	"net"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type NATpmpChecker struct{}

type NATpmpConfig struct{}

func NewNATpmpChecker() checker.Checker {
	return &NATpmpChecker{}
}

func (c *NATpmpChecker) Name() string {
	return "natpmp"
}

func (c *NATpmpChecker) Description() string {
	return "NAT Port Mapping Protocol detection"
}

func (c *NATpmpChecker) Icon() string {
	return "🔗"
}

func (c *NATpmpChecker) DefaultConfig() checker.CheckerConfig {
	return NATpmpConfig{}
}

func (c *NATpmpChecker) RequiresRouter() bool {
	return true
}

func (c *NATpmpChecker) DefaultEnabled() bool {
	return true
}

func (c *NATpmpChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyGateway, checker.DependencyRouterInfo}
}

func (c *NATpmpChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	checkNATpmp(router, out)
}

func (c *NATpmpChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
	// Router-based checker - no standalone functionality
}

func (c *NATpmpChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_natpmp",
		Description: "Test for NAT Port Mapping Protocol (NAT-PMP) service on router",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func checkNATpmp(router *common.RouterInfo, out output.Output) {
	out.Section("🔍", "Checking NAT-PMP...")
	out.Debug("NAT-PMP: Checking gateway %s on port 5351", router.IP)
	// Send NAT-PMP external address request
	if sendNATpmpRequest(router.IP, out) {
		router.NATpmpEnabled = true
		out.Info("📡 NAT-PMP service detected")
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityMedium,
			Description: "NAT-PMP service is enabled",
			Details:     "NAT-PMP allows automatic port mapping. Ensure it's properly secured.",
		})
	} else {
		out.Debug("NAT-PMP: No service detected on %s", router.IP)
		out.Success("No NAT-PMP service detected")
	}
}

func sendNATpmpRequest(gatewayIP string, out output.Output) bool {
	out.Debug("NAT-PMP: Connecting to %s:5351", gatewayIP)
	conn, err := net.Dial("udp", gatewayIP+":5351")
	if err != nil {
		out.Debug("NAT-PMP: Failed to connect: %v", err)
		return false
	}
	defer conn.Close()

	// NAT-PMP external address request: version=0, opcode=0
	request := []byte{0, 0}
	out.Debug("NAT-PMP: Sending external address request")

	conn.SetDeadline(time.Now().Add(common.NATpmpTimeout))
	_, err = conn.Write(request)
	if err != nil {
		out.Debug("NAT-PMP: Failed to write request: %v", err)
		return false
	}

	response := make([]byte, 12)
	n, err := conn.Read(response)
	if err != nil || n < 8 {
		out.Debug("NAT-PMP: Failed to read response (n=%d): %v", n, err)
		return false
	}

	out.Debug("NAT-PMP: Received response (%d bytes): version=%d opcode=%d result=%d",
		n, response[0], response[1], response[2])

	// Check if response is valid NAT-PMP response
	// Version should be 0, opcode should be 128 (0x80 + 0), result should be 0 for success
	isValid := response[0] == 0 && response[1] == 128 && response[2] == 0 && response[3] == 0
	if isValid {
		out.Debug("NAT-PMP: Valid response received")
	} else {
		out.Debug("NAT-PMP: Invalid response format")
	}
	return isValid
}
