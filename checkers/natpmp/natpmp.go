package natpmp

import (
	"fmt"
	"net"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
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

func (c *NATpmpChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	checkNATpmp(router)
}

func (c *NATpmpChecker) RunStandalone(config checker.CheckerConfig) {
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

func checkNATpmp(router *common.RouterInfo) {
	fmt.Println("\n🔍 Checking NAT-PMP...")
	// Send NAT-PMP external address request
	if sendNATpmpRequest(router.IP) {
		router.NATpmpEnabled = true
		fmt.Println("  📡 NAT-PMP service detected")
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityMedium,
			Description: "NAT-PMP service is enabled",
			Details:     "NAT-PMP allows automatic port mapping. Ensure it's properly secured.",
		})
	} else {
		fmt.Println("  ✅ No NAT-PMP service detected")
	}
}

func sendNATpmpRequest(gatewayIP string) bool {
	conn, err := net.Dial("udp", gatewayIP+":5351")
	if err != nil {
		return false
	}
	defer conn.Close()

	// NAT-PMP external address request: version=0, opcode=0
	request := []byte{0, 0}

	conn.SetDeadline(time.Now().Add(common.NATpmpTimeout))
	_, err = conn.Write(request)
	if err != nil {
		return false
	}

	response := make([]byte, 12)
	n, err := conn.Read(response)
	if err != nil || n < 8 {
		return false
	}

	// Check if response is valid NAT-PMP response
	// Version should be 0, opcode should be 128 (0x80 + 0), result should be 0 for success
	return response[0] == 0 && response[1] == 128 && response[2] == 0 && response[3] == 0
}
