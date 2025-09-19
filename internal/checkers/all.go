package checkers

import (
	"fmt"

	"github.com/R167/netcheck/internal/mcp"
)

func CheckAll(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
	allIssues := []mcp.Issue{}
	report := fmt.Sprintf("Comprehensive Network Security Check\nGateway IP: %s\n\n", input.GatewayIP)

	webResult, _ := CheckWebInterface(input)
	if webResult != nil {
		allIssues = append(allIssues, webResult.Issues...)
		report += "=== Web Interface ===\n" + webResult.Report + "\n\n"
	}

	portsResult, _ := ScanPorts(input)
	if portsResult != nil {
		allIssues = append(allIssues, portsResult.Issues...)
		report += "=== Port Scan ===\n" + portsResult.Report + "\n\n"
	}

	return &mcp.CheckToolOutput{
		Issues:  allIssues,
		Summary: fmt.Sprintf("Comprehensive scan found %d total issues", len(allIssues)),
		Report:  report,
	}, nil
}