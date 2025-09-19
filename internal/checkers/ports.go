package checkers

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/R167/netcheck/internal/mcp"
)

func ScanPorts(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
	ports := input.Ports
	if len(ports) == 0 {
		ports = []int{22, 23, 80, 443, 8080, 8443, 21, 53, 161, 8291}
	}

	var openPorts []int
	var issues []mcp.Issue

	for _, port := range ports {
		if isPortOpen(input.GatewayIP, port, time.Second) {
			openPorts = append(openPorts, port)

			if issue := getPortSecurityIssue(port); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}

	report := fmt.Sprintf("Gateway IP: %s\n\nOpen Ports: %v\n\nIssues: %d\n", input.GatewayIP, openPorts, len(issues))
	for i, issue := range issues {
		report += fmt.Sprintf("\n%d. [%s] %s\n   %s\n", i+1, issue.Severity, issue.Description, issue.Details)
	}

	return &mcp.CheckToolOutput{
		Issues:  issues,
		Summary: fmt.Sprintf("Found %d open ports, %d security issues", len(openPorts), len(issues)),
		Report:  report,
	}, nil
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getPortSecurityIssue(port int) *mcp.Issue {
	issues := map[int]mcp.Issue{
		22: {
			Severity:    "MEDIUM",
			Description: "SSH service exposed",
			Details:     "SSH is accessible from the network. Ensure strong authentication is configured.",
		},
		23: {
			Severity:    "HIGH",
			Description: "Telnet service exposed",
			Details:     "Telnet transmits data in plain text. Consider disabling if not needed.",
		},
		161: {
			Severity:    "MEDIUM",
			Description: "SNMP service exposed",
			Details:     "SNMP can expose device information. Ensure community strings are changed from defaults.",
		},
	}

	if issue, ok := issues[port]; ok {
		return &issue
	}
	return nil
}