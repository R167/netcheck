package mcp

import (
	"context"
	"fmt"
	"log"
	"strings"

	"net"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolHandler is the function signature for MCP tool handlers.
type ToolHandler func(ctx context.Context, input *ToolInput) (*ToolOutput, error)

// ServerConfig holds configuration for the MCP server.
type ServerConfig struct {
	// AllCheckers returns all available checker implementations.
	AllCheckers func() []checker.Checker
	// DiscoverGateway finds the network gateway IP.
	DiscoverGateway func() string
}

// RunServer starts the MCP server with all tools auto-registered from the checker registry.
func RunServer(cfg ServerConfig) error {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "netcheck",
		Version: "2.0.0",
	}, nil)

	// Register the network discovery tool.
	registerDiscoverNetwork(server, cfg)

	// Register the full scan tool.
	registerFullScan(server, cfg)

	// Auto-register all checker tools.
	for _, c := range cfg.AllCheckers() {
		registerChecker(server, c)
	}

	if err := server.Run(context.Background(), &mcpsdk.StdioTransport{}); err != nil {
		log.Printf("MCP server failed: %v", err)
		return err
	}
	return nil
}

// registerChecker registers a single checker as an MCP tool.
func registerChecker(server *mcpsdk.Server, c checker.Checker) {
	toolDef := c.MCPToolDefinition()
	requiresRouter := c.RequiresRouter()
	checkerName := c.Name()

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        toolDef.Name,
		Description: toolDef.Description,
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest, input ToolInput) (*mcpsdk.CallToolResult, ToolOutput, error) {
		buf := output.NewBufferedOutput()
		router := newRouterInfo(input.GatewayIP)

		cfg := configFromInput(checkerName, c.DefaultConfig(), input)

		if requiresRouter {
			if input.GatewayIP == "" {
				return nil, ToolOutput{}, fmt.Errorf("gateway_ip is required for %s", checkerName)
			}
			c.Run(cfg, router, buf)
		} else {
			c.RunStandalone(cfg, buf)
		}

		var result ToolOutput
		if requiresRouter {
			result = buildToolOutput(router, buf)
			populateServices(&result, router)
		} else {
			result = buildStandaloneOutput(buf)
		}
		result.Summary = fmt.Sprintf("%s: found %d issues", checkerName, len(result.Issues))

		return textResult(result)
	})
}

// registerDiscoverNetwork registers the discover_network tool, which is the
// starting point for network investigation.
func registerDiscoverNetwork(server *mcpsdk.Server, cfg ServerConfig) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "discover_network",
		Description: "Discover the local network: find the gateway IP, list network interfaces, and gather basic network topology. This is the recommended first step before running any other checks.",
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest, input ToolInput) (*mcpsdk.CallToolResult, ToolOutput, error) {
		gatewayIP := cfg.DiscoverGateway()

		gateway := &GatewayInfo{IP: gatewayIP}
		gateway.Interfaces = discoverInterfaces()

		result := ToolOutput{
			Gateway: gateway,
		}

		if gatewayIP == "" {
			result.Summary = "Could not determine gateway IP"
		} else {
			result.Summary = fmt.Sprintf("Gateway discovered at %s", gatewayIP)
		}

		return textResult(result)
	})
}

// registerFullScan registers the full_scan tool, which runs multiple checks
// against a gateway in a single call.
func registerFullScan(server *mcpsdk.Server, cfg ServerConfig) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "full_scan",
		Description: "Run a comprehensive security scan against a network gateway. Runs web interface, port scan, UPnP, NAT-PMP, IPv6, SSDP, and API checks. Use discover_network first to find the gateway IP.",
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest, input ToolInput) (*mcpsdk.CallToolResult, ToolOutput, error) {
		if input.GatewayIP == "" {
			return nil, ToolOutput{}, fmt.Errorf("gateway_ip is required for full_scan")
		}

		buf := output.NewBufferedOutput()
		router := newRouterInfo(input.GatewayIP)

		// Determine which checkers to run.
		requestedSet := make(map[string]bool)
		for _, name := range input.Checkers {
			requestedSet[name] = true
		}

		for _, c := range cfg.AllCheckers() {
			// Skip if specific checkers were requested and this isn't one of them.
			if len(requestedSet) > 0 && !requestedSet[c.Name()] {
				continue
			}
			// In default mode, only run default-enabled checks.
			if len(requestedSet) == 0 && !c.DefaultEnabled() {
				continue
			}

			checkerCfg := configFromInput(c.Name(), c.DefaultConfig(), input)
			if c.RequiresRouter() {
				c.Run(checkerCfg, router, buf)
			} else {
				c.RunStandalone(checkerCfg, buf)
			}
		}

		result := buildToolOutput(router, buf)
		populateServices(&result, router)

		issueCount := len(result.Issues)
		serviceCount := len(result.Services)
		result.Summary = fmt.Sprintf("Full scan complete: %d issues, %d services discovered", issueCount, serviceCount)

		return textResult(result)
	})
}

// textResult wraps a ToolOutput into the MCP return triple.
func textResult(result ToolOutput) (*mcpsdk.CallToolResult, ToolOutput, error) {
	text := formatResultAsText(result)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{
			&mcpsdk.TextContent{Text: text},
		},
	}, result, nil
}

// newRouterInfo creates a properly initialized RouterInfo.
func newRouterInfo(gatewayIP string) *common.RouterInfo {
	return &common.RouterInfo{
		IP:           gatewayIP,
		OpenPorts:    []int{},
		Issues:       []common.SecurityIssue{},
		MDNSServices: []common.MDNSService{},
		PortMappings: []common.PortMapping{},
		IPv6Pinholes: []common.IPv6Pinhole{},
		UPnPServices: []common.UPnPService{},
		SSDPServices: []common.SSDPService{},
	}
}

// buildToolOutput creates a ToolOutput from router state and buffered output.
func buildToolOutput(router *common.RouterInfo, buf *output.BufferedOutput) ToolOutput {
	return ToolOutput{
		Router: RouterStateFromInfo(router),
		Issues: IssuesFromInfo(router.Issues),
		Log:    renderBufferedOutput(buf),
	}
}

// buildStandaloneOutput creates a ToolOutput with no router state.
func buildStandaloneOutput(buf *output.BufferedOutput) ToolOutput {
	return ToolOutput{
		Log: renderBufferedOutput(buf),
	}
}

// populateServices fills service and port mapping fields from router state.
func populateServices(result *ToolOutput, router *common.RouterInfo) {
	if len(router.MDNSServices) > 0 {
		result.Services = append(result.Services, ServicesFromMDNS(router.MDNSServices)...)
	}
	if len(router.SSDPServices) > 0 {
		result.Services = append(result.Services, ServicesFromSSDP(router.SSDPServices)...)
	}
	if len(router.UPnPServices) > 0 {
		result.Services = append(result.Services, ServicesFromUPnP(router.UPnPServices)...)
	}
	if len(router.PortMappings) > 0 {
		result.PortMappings = router.PortMappings
	}
}

// renderBufferedOutput converts buffered output lines to a single string.
func renderBufferedOutput(buf *output.BufferedOutput) string {
	lines := buf.Lines()
	parts := make([]string, len(lines))
	for i, line := range lines {
		parts[i] = line.Message
	}
	return strings.Join(parts, "\n")
}

// formatResultAsText creates a human-readable summary for MCP text content.
func formatResultAsText(result ToolOutput) string {
	var sb strings.Builder

	sb.WriteString(result.Summary)
	sb.WriteString("\n\n")

	if result.Gateway != nil {
		sb.WriteString("## Network Discovery\n")
		if result.Gateway.IP != "" {
			sb.WriteString(fmt.Sprintf("Gateway: %s\n", result.Gateway.IP))
		}
		if result.Gateway.ExternalIP != "" {
			sb.WriteString(fmt.Sprintf("External IP: %s\n", result.Gateway.ExternalIP))
		}
		sb.WriteString("\n")
	}

	if result.Router != nil {
		sb.WriteString("## Router State\n")
		sb.WriteString(fmt.Sprintf("IP: %s\n", result.Router.IP))
		if result.Router.Vendor != "" {
			sb.WriteString(fmt.Sprintf("Vendor: %s\n", result.Router.Vendor))
		}
		if result.Router.Model != "" {
			sb.WriteString(fmt.Sprintf("Model: %s\n", result.Router.Model))
		}
		if len(result.Router.OpenPorts) > 0 {
			sb.WriteString(fmt.Sprintf("Open Ports: %v\n", result.Router.OpenPorts))
		}
		sb.WriteString("\n")
	}

	if len(result.Issues) > 0 {
		sb.WriteString(fmt.Sprintf("## Security Issues (%d)\n", len(result.Issues)))
		for i, iss := range result.Issues {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n   %s\n", i+1, iss.Severity, iss.Description, iss.Details))
		}
		sb.WriteString("\n")
	}

	if len(result.Services) > 0 {
		sb.WriteString(fmt.Sprintf("## Discovered Services (%d)\n", len(result.Services)))
		for _, svc := range result.Services {
			if svc.IP != "" && svc.Port > 0 {
				sb.WriteString(fmt.Sprintf("- %s (%s) at %s:%d\n", svc.Name, svc.Type, svc.IP, svc.Port))
			} else {
				sb.WriteString(fmt.Sprintf("- %s (%s)\n", svc.Name, svc.Type))
			}
		}
		sb.WriteString("\n")
	}

	if len(result.PortMappings) > 0 {
		sb.WriteString(fmt.Sprintf("## Port Mappings (%d)\n", len(result.PortMappings)))
		for _, pm := range result.PortMappings {
			desc := pm.Description
			if desc == "" {
				desc = "no description"
			}
			sb.WriteString(fmt.Sprintf("- %s:%d -> %s:%d (%s)\n",
				pm.Protocol, pm.ExternalPort, pm.InternalIP, pm.InternalPort, desc))
		}
		sb.WriteString("\n")
	}

	if result.Log != "" {
		sb.WriteString("## Details\n")
		sb.WriteString(result.Log)
		sb.WriteString("\n")
	}

	return sb.String()
}

// discoverInterfaces returns info about non-loopback network interfaces.
func discoverInterfaces() []NetIf {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []NetIf
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		var addrStrs []string
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		result = append(result, NetIf{
			Name:  iface.Name,
			Addrs: addrStrs,
			MAC:   iface.HardwareAddr.String(),
			Flags: iface.Flags.String(),
		})
	}
	return result
}
