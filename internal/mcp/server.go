package mcp

import (
	"context"
	"log"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type CheckFunction func(input *CheckToolInput) (*CheckToolOutput, error)

type CheckerRegistry struct {
	checkers map[string]CheckFunction
}

func NewCheckerRegistry() *CheckerRegistry {
	return &CheckerRegistry{
		checkers: make(map[string]CheckFunction),
	}
}

func (r *CheckerRegistry) Register(name string, fn CheckFunction) {
	r.checkers[name] = fn
}

func RunServer(registry *CheckerRegistry) error {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "netcheck",
		Version: "1.0.0",
	}, nil)

	for name, checker := range registry.checkers {
		addChecker(server, name, checker)
	}

	if err := server.Run(context.Background(), &mcpsdk.StdioTransport{}); err != nil {
		log.Printf("MCP server failed: %v", err)
		return err
	}

	return nil
}

func addChecker(server *mcpsdk.Server, name string, fn CheckFunction) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        name,
		Description: getDescription(name),
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest, input CheckToolInput) (*mcpsdk.CallToolResult, CheckToolOutput, error) {
		output, err := fn(&input)
		if err != nil {
			return nil, CheckToolOutput{}, err
		}

		return &mcpsdk.CallToolResult{
			Content: []mcpsdk.Content{
				&mcpsdk.TextContent{Text: output.Report},
			},
		}, *output, nil
	})
}

func getDescription(name string) string {
	descriptions := map[string]string{
		"check_web_interface": "Check router web interface for default credentials and security issues",
		"scan_ports":          "Scan common management ports on a router",
		"check_all":           "Run all available security checks on the router",
		"check_upnp":          "Check for UPnP services and enumerate port mappings",
		"check_natpmp":        "Check for NAT-PMP services",
		"check_ipv6":          "Check IPv6 configuration and connectivity",
		"check_mdns":          "Perform comprehensive mDNS service discovery",
		"check_router_apis":   "Check for exposed router APIs and services",
		"check_starlink":      "Check for Starlink Dishy and security issues",
		"check_routes":        "Display routing information",
		"check_device":        "Display interface/device information",
		"check_external":      "Discover external IPv4/IPv6 addresses",
		"check_lldp":          "Link layer discovery and debugging",
	}

	if desc, ok := descriptions[name]; ok {
		return desc
	}
	return name
}