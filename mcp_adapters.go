package main

import (
	"fmt"
	"strings"

	"github.com/R167/netcheck/internal/mcp"
)

func adaptWebCheck(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
	router := &RouterInfo{
		IP:     input.GatewayIP,
		Issues: []SecurityIssue{},
	}

	checkWebInterface(router)

	issues := make([]mcp.Issue, len(router.Issues))
	for i, iss := range router.Issues {
		issues[i] = mcp.Issue{
			Severity:    iss.Severity,
			Description: iss.Description,
			Details:     iss.Details,
		}
	}

	report := formatMCPReport(router)

	return &mcp.CheckToolOutput{
		Issues:  issues,
		Summary: fmt.Sprintf("Found %d issues", len(issues)),
		Report:  report,
	}, nil
}

func adaptPortScan(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
	router := &RouterInfo{
		IP:        input.GatewayIP,
		Issues:    []SecurityIssue{},
		OpenPorts: []int{},
	}

	scanCommonPorts(router)

	issues := make([]mcp.Issue, len(router.Issues))
	for i, iss := range router.Issues {
		issues[i] = mcp.Issue{
			Severity:    iss.Severity,
			Description: iss.Description,
			Details:     iss.Details,
		}
	}

	report := formatMCPReport(router)

	return &mcp.CheckToolOutput{
		Issues:  issues,
		Summary: fmt.Sprintf("Found %d open ports, %d issues", len(router.OpenPorts), len(issues)),
		Report:  report,
	}, nil
}

func formatMCPReport(router *RouterInfo) string {
	report := fmt.Sprintf("Router IP: %s\n", router.IP)
	if router.Vendor != "" {
		report += fmt.Sprintf("Vendor: %s\n", strings.Title(router.Vendor))
	}
	if router.Model != "" {
		report += fmt.Sprintf("Model: %s\n", router.Model)
	}

	report += fmt.Sprintf("\nOpen Ports: %v\n", router.OpenPorts)
	report += fmt.Sprintf("Issues: %d\n", len(router.Issues))

	for i, issue := range router.Issues {
		report += fmt.Sprintf("\n%d. [%s] %s\n   %s\n", i+1, issue.Severity, issue.Description, issue.Details)
	}

	return report
}