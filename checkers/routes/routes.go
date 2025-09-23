package routes

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
)

type RoutesChecker struct{}

type RoutesConfig struct{}

func NewRoutesChecker() checker.Checker {
	return &RoutesChecker{}
}

func (c *RoutesChecker) Name() string {
	return "routes"
}

func (c *RoutesChecker) Description() string {
	return "System routing table analysis"
}

func (c *RoutesChecker) Icon() string {
	return "📍"
}

func (c *RoutesChecker) DefaultConfig() checker.CheckerConfig {
	return RoutesConfig{}
}

func (c *RoutesChecker) RequiresRouter() bool {
	return false
}

func (c *RoutesChecker) DefaultEnabled() bool {
	return true
}

func (c *RoutesChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{}
}

func (c *RoutesChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	// Standalone checker - no router-based functionality
}

func (c *RoutesChecker) RunStandalone(config checker.CheckerConfig) {
	checkRoutes()
}

func (c *RoutesChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_routes",
		Description: "Display system routing table information for both IPv4 and IPv6",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
			"required":   []string{},
		},
	}
}

// checkRoutes displays the system's routing table information
func checkRoutes() {
	fmt.Println("📍 Routing Information")
	fmt.Println("=====================")

	// Get IPv4 routes
	ipv4Routes := getIPv4Routes()
	if len(ipv4Routes) > 0 {
		fmt.Printf("  📡 IPv4 Routes (%d entries):\n", len(ipv4Routes))
		for _, route := range ipv4Routes {
			fmt.Printf("    %s\n", route)
		}
		fmt.Println()
	}

	// Get IPv6 routes
	ipv6Routes := getIPv6Routes()
	if len(ipv6Routes) > 0 {
		fmt.Printf("  🌐 IPv6 Routes (%d entries):\n", len(ipv6Routes))
		for _, route := range ipv6Routes {
			fmt.Printf("    %s\n", route)
		}
		fmt.Println()
	}

	if len(ipv4Routes) == 0 && len(ipv6Routes) == 0 {
		fmt.Println("  ℹ️  No routing information available")
	}
}

// getIPv4Routes retrieves IPv4 routing table information
func getIPv4Routes() []string {
	var routes []string

	// Try netstat first (most portable)
	cmd := exec.Command("netstat", "-rn", "-f", "inet")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		inRoutes := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Destination") && strings.Contains(line, "Gateway") {
				inRoutes = true
				continue
			}
			if inRoutes && line != "" && !strings.HasPrefix(line, "Internet") {
				// Clean up the route display
				if strings.Fields(line)[0] != "" {
					routes = append(routes, formatRoute(line))
				}
			}
		}
		if len(routes) > 0 {
			return routes
		}
	}

	// Try route command on Linux
	cmd = exec.Command("route", "-n")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if i == 0 || line == "" {
				continue
			}
			if strings.Contains(line, "Destination") || strings.Contains(line, "Kernel") {
				continue
			}
			routes = append(routes, formatRouteLinux(line))
		}
		if len(routes) > 0 {
			return routes
		}
	}

	// Try ip route on modern Linux
	cmd = exec.Command("ip", "route", "show")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				routes = append(routes, line)
			}
		}
	}

	return routes
}

// getIPv6Routes retrieves IPv6 routing table information
func getIPv6Routes() []string {
	var routes []string

	// Try netstat for IPv6
	cmd := exec.Command("netstat", "-rn", "-f", "inet6")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		inRoutes := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Destination") && strings.Contains(line, "Gateway") {
				inRoutes = true
				continue
			}
			if inRoutes && line != "" && !strings.HasPrefix(line, "Internet6") {
				if strings.Fields(line)[0] != "" {
					routes = append(routes, formatRoute(line))
				}
			}
		}
		if len(routes) > 0 {
			return routes
		}
	}

	// Try ip -6 route on Linux
	cmd = exec.Command("ip", "-6", "route", "show")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				routes = append(routes, line)
			}
		}
	}

	return routes
}

// formatRoute formats a route line for display
func formatRoute(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 3 {
		dest := fields[0]
		gateway := fields[1]
		if gateway == "0.0.0.0" || gateway == "::" {
			gateway = "direct"
		}
		return fmt.Sprintf("%s → %s", dest, gateway)
	}
	return line
}

// formatRouteLinux formats a Linux route command output
func formatRouteLinux(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 8 {
		dest := fields[0]
		gateway := fields[1]
		if gateway == "0.0.0.0" {
			gateway = "direct"
		}
		return fmt.Sprintf("%s → %s", dest, gateway)
	}
	return line
}
