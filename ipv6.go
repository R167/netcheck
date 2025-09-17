package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// IPv6AddressInfo represents detailed information about an IPv6 address
type IPv6AddressInfo struct {
	Address     string
	Prefix      string
	Interface   string
	Type        string
	Scope       string
	Status      string
	Source      string
	Preferred   bool
	Temporary   bool
	Deprecated  bool
}

// IPv6InterfaceInfo represents IPv6 configuration for an interface
type IPv6InterfaceInfo struct {
	Name              string
	Addresses         []IPv6AddressInfo
	LinkLocalAddress  string
	GlobalAddresses   []string
	ULAAddresses      []string
	TempAddresses     []string
	RouterAddress     string
	MTU               int
	HopLimit          int
	Flags             []string
}

func checkIPv6(router *RouterInfo) {
	fmt.Println("\n🔍 Checking IPv6 configuration...")

	// Get comprehensive IPv6 information
	ipv6Info := getIPv6Information()

	if len(ipv6Info) == 0 {
		fmt.Println("  ℹ️  No IPv6 configuration detected")
		return
	}

	router.IPv6Enabled = true

	// Analyze and display IPv6 configuration
	analyzeIPv6Configuration(ipv6Info, router)

	// Check for potential security issues
	assessIPv6Security(ipv6Info, router)

	// Test IPv6 gateway connectivity
	testIPv6Gateway(router)
}

// getIPv6Information gathers comprehensive IPv6 configuration data
func getIPv6Information() []IPv6InterfaceInfo {
	var interfaces []IPv6InterfaceInfo

	// Get Go's view of interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		// Skip virtual interfaces unless --show-virtual flag is set
		if !*showVirtualFlag && isVirtualInterface(iface.Name) {
			continue
		}

		ipv6Info := IPv6InterfaceInfo{
			Name: iface.Name,
			MTU:  iface.MTU,
		}

		// Check if interface is up
		if iface.Flags&net.FlagUp != 0 {
			ipv6Info.Flags = append(ipv6Info.Flags, "UP")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			ipv6Info.Flags = append(ipv6Info.Flags, "LOOPBACK")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			ipv6Info.Flags = append(ipv6Info.Flags, "MULTICAST")
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		hasIPv6 := false
		for _, addr := range addrs {
			if ip, network, err := net.ParseCIDR(addr.String()); err == nil {
				if ip.To4() == nil { // IPv6 address
					hasIPv6 = true
					addrInfo := IPv6AddressInfo{
						Address:   ip.String(),
						Prefix:    network.String(),
						Interface: iface.Name,
						Type:      classifyIPv6Address(ip),
						Scope:     getIPv6Scope(ip),
						Status:    "active",
					}

					// Determine if this is a temporary address
					if isTemporaryIPv6(ip) {
						addrInfo.Temporary = true
						addrInfo.Source = "Privacy Extensions"
						ipv6Info.TempAddresses = append(ipv6Info.TempAddresses, ip.String())
					}

					// Categorize addresses
					switch addrInfo.Type {
					case "Link-Local":
						ipv6Info.LinkLocalAddress = ip.String()
					case "Global Unicast":
						ipv6Info.GlobalAddresses = append(ipv6Info.GlobalAddresses, ip.String())
					case "Unique Local":
						ipv6Info.ULAAddresses = append(ipv6Info.ULAAddresses, ip.String())
					}

					ipv6Info.Addresses = append(ipv6Info.Addresses, addrInfo)
				}
			}
		}

		// Only include interfaces with IPv6 addresses
		if hasIPv6 {
			// Try to get additional system-specific information
			enhanceIPv6Info(&ipv6Info)
			interfaces = append(interfaces, ipv6Info)
		}
	}

	return interfaces
}

// classifyIPv6Address determines the type of IPv6 address
func classifyIPv6Address(ip net.IP) string {
	if ip.IsLoopback() {
		return "Loopback"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link-Local"
	}
	if ip.IsMulticast() {
		return "Multicast"
	}
	if isIPv6ULA(ip) {
		return "Unique Local"
	}
	if isIPv6Global(ip) {
		return "Global Unicast"
	}
	if isIPv6DocumentationPrefix(ip) {
		return "Documentation"
	}
	if isIPv6Teredo(ip) {
		return "Teredo"
	}
	if isIPv66to4(ip) {
		return "6to4"
	}
	return "Other"
}

// getIPv6Scope determines the scope of an IPv6 address
func getIPv6Scope(ip net.IP) string {
	if ip.IsLoopback() {
		return "Host"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link"
	}
	if isIPv6ULA(ip) {
		return "Site"
	}
	if ip.IsMulticast() {
		// Extract scope from multicast address
		if len(ip) >= 16 {
			scope := ip[1] & 0x0F
			switch scope {
			case 1:
				return "Interface-Local"
			case 2:
				return "Link-Local"
			case 4:
				return "Admin-Local"
			case 5:
				return "Site-Local"
			case 8:
				return "Organization-Local"
			case 14:
				return "Global"
			}
		}
		return "Multicast"
	}
	return "Global"
}

// Helper functions for IPv6 address classification
func isIPv6ULA(ip net.IP) bool {
	return len(ip) == 16 && ip[0] == 0xfc || ip[0] == 0xfd
}

func isIPv6Global(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	// Global unicast addresses start with 2000::/3
	return ip[0]&0xE0 == 0x20
}

func isIPv6DocumentationPrefix(ip net.IP) bool {
	// 2001:db8::/32
	return len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8
}

func isIPv6Teredo(ip net.IP) bool {
	// 2001::/32
	return len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00
}

func isIPv66to4(ip net.IP) bool {
	// 2002::/16
	return len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x02
}

func isTemporaryIPv6(ip net.IP) bool {
	// This is a heuristic - temporary addresses often have random patterns
	// Real detection would require system calls or parsing system information
	if !isIPv6Global(ip) {
		return false
	}

	// Check if it looks like a temporary address (has randomized interface ID)
	// This is a simplified heuristic
	return len(ip) == 16 && (ip[8]&0x02) == 0 // Universal/Local bit not set typically indicates temp
}

// enhanceIPv6Info adds system-specific IPv6 information
func enhanceIPv6Info(info *IPv6InterfaceInfo) {
	// Try to get additional info from system commands
	if hopLimit := getIPv6HopLimit(info.Name); hopLimit > 0 {
		info.HopLimit = hopLimit
	}

	// Try to find router address from neighbor discovery
	if router := getIPv6Router(info.Name); router != "" {
		info.RouterAddress = router
	}
}

// getIPv6HopLimit tries to get the hop limit for an interface
func getIPv6HopLimit(ifaceName string) int {
	// Try different system commands to get hop limit
	commands := [][]string{
		{"sysctl", "-n", fmt.Sprintf("net.inet6.ip6.hlim")}, // macOS
		{"cat", fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/hop_limit", ifaceName)}, // Linux
	}

	for _, cmd := range commands {
		if output, err := exec.Command(cmd[0], cmd[1:]...).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				// Parse the number if possible
				if hlim := strings.TrimSpace(string(output)); hlim != "" {
					return 64 // Default if we can't parse
				}
			}
		}
	}
	return 0
}

// getIPv6Router tries to find the IPv6 router address
func getIPv6Router(ifaceName string) string {
	// Try different methods to find router
	commands := [][]string{
		{"route", "-n", "get", "-inet6", "default"}, // macOS
		{"ip", "-6", "route", "show", "default"},     // Linux
	}

	for _, cmd := range commands {
		if output, err := exec.Command(cmd[0], cmd[1:]...).Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "gateway") || strings.Contains(line, "via") {
					fields := strings.Fields(line)
					for i, field := range fields {
						if (field == "gateway:" || field == "via") && i+1 < len(fields) {
							return fields[i+1]
						}
					}
				}
			}
		}
	}
	return ""
}

// analyzeIPv6Configuration displays comprehensive IPv6 analysis
func analyzeIPv6Configuration(interfaces []IPv6InterfaceInfo, router *RouterInfo) {
	totalAddresses := 0
	globalInterfaces := 0
	linkLocalInterfaces := 0
	tempAddresses := 0

	fmt.Printf("  🌐 IPv6 is enabled on %d interface(s)\n", len(interfaces))

	for _, iface := range interfaces {
		if len(iface.Addresses) == 0 {
			continue
		}

		fmt.Printf("\n  📡 Interface: %s\n", iface.Name)

		// Display address breakdown
		for _, addr := range iface.Addresses {
			totalAddresses++
			statusIcon := getIPv6StatusIcon(addr)
			if addr.Temporary {
				tempAddresses++
			}

			fmt.Printf("    %s %s (%s, %s scope)\n", statusIcon, addr.Address, addr.Type, addr.Scope)
			if addr.Prefix != addr.Address {
				fmt.Printf("       Network: %s\n", addr.Prefix)
			}
		}

		// Count interface types
		if len(iface.GlobalAddresses) > 0 {
			globalInterfaces++
		}
		if iface.LinkLocalAddress != "" {
			linkLocalInterfaces++
		}

		// Display router if found
		if iface.RouterAddress != "" {
			fmt.Printf("    🔗 Router: %s\n", iface.RouterAddress)
		}

		// Display flags and configuration
		if len(iface.Flags) > 0 {
			fmt.Printf("    ⚙️  Flags: %s\n", strings.Join(iface.Flags, ", "))
		}
	}

	// Summary statistics
	fmt.Printf("\n  📊 IPv6 Summary:\n")
	fmt.Printf("    • Total addresses: %d\n", totalAddresses)
	fmt.Printf("    • Global interfaces: %d\n", globalInterfaces)
	fmt.Printf("    • Link-local interfaces: %d\n", linkLocalInterfaces)
	if tempAddresses > 0 {
		fmt.Printf("    • Temporary addresses: %d (Privacy Extensions enabled)\n", tempAddresses)
	}
}

// assessIPv6Security performs security assessment of IPv6 configuration
func assessIPv6Security(interfaces []IPv6InterfaceInfo, router *RouterInfo) {
	hasGlobal := false
	hasTemporary := false
	hasULA := false

	for _, iface := range interfaces {
		if len(iface.GlobalAddresses) > 0 {
			hasGlobal = true
		}
		if len(iface.TempAddresses) > 0 {
			hasTemporary = true
		}
		if len(iface.ULAAddresses) > 0 {
			hasULA = true
		}
	}

	// Security assessments
	if hasGlobal {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: "IPv6 global addresses detected",
			Details:     "IPv6 global addresses are reachable from the internet. Ensure IPv6 firewall rules are properly configured to prevent unauthorized access.",
		})
	}

	if hasTemporary {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "LOW",
			Description: "IPv6 Privacy Extensions enabled",
			Details:     "Temporary IPv6 addresses provide privacy benefits by changing periodically, making device tracking more difficult.",
		})
	}

	if hasULA {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "LOW",
			Description: "IPv6 Unique Local Addresses (ULA) in use",
			Details:     "ULA addresses provide local connectivity but should not be routed globally. Verify network configuration.",
		})
	}

	// Check for missing privacy extensions on global addresses
	if hasGlobal && !hasTemporary {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: "IPv6 Privacy Extensions not enabled",
			Details:     "Consider enabling IPv6 Privacy Extensions to generate temporary addresses that change periodically, improving privacy.",
		})
	}
}

// testIPv6Gateway tests connectivity to IPv6 gateways
func testIPv6Gateway(router *RouterInfo) {
	fmt.Printf("\n  🔍 Testing IPv6 gateway connectivity...\n")

	// Common IPv6 gateway patterns to test
	gatewayPatterns := []string{
		"fe80::1",           // Common link-local gateway
		"::1",               // Loopback
		"2001:4860:4860::8888", // Google DNS
		"2606:4700:4700::1111", // Cloudflare DNS
	}

	reachableGateways := 0

	for _, gateway := range gatewayPatterns {
		if testIPv6Connectivity(gateway) {
			reachableGateways++
			fmt.Printf("    ✅ %s reachable\n", gateway)

			if gateway == "fe80::1" {
				fmt.Printf("    📡 Local IPv6 gateway detected\n")
			}
		}
	}

	if reachableGateways > 0 {
		fmt.Printf("  🌐 IPv6 internet connectivity appears functional\n")

		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: "IPv6 internet connectivity active",
			Details:     "Device has active IPv6 internet connectivity. Ensure IPv6 firewall rules match IPv4 security policies.",
		})
	} else {
		fmt.Printf("  ⚠️  No IPv6 gateways reachable (local IPv6 only)\n")
	}
}

// testIPv6Connectivity tests if an IPv6 address is reachable
func testIPv6Connectivity(address string) bool {
	// Try to connect to common ports
	ports := []string{"80", "443", "53"}

	for _, port := range ports {
		conn, err := net.DialTimeout("tcp6", "["+address+"]:"+port, 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Try ICMP ping if TCP fails (simplified check)
	return false
}

// getIPv6StatusIcon returns the appropriate emoji for an IPv6 address based on its type and characteristics
func getIPv6StatusIcon(addr IPv6AddressInfo) string {
	// Temporary addresses (Privacy Extensions) - yellow circle
	if addr.Temporary {
		return "🟡"
	}

	// Different icons based on address type
	switch addr.Type {
	case "Link-Local":
		return "🔗" // Chain link for link-local (local network only)
	case "Loopback":
		return "🔄" // Loop for loopback
	case "Global Unicast":
		return "🌐" // Globe for global/internet addresses
	case "Unique Local":
		return "🏠" // House for ULA (site-local)
	case "Multicast":
		return "📢" // Megaphone for multicast
	case "Teredo":
		return "🌉" // Bridge for tunneling
	case "6to4":
		return "🌉" // Bridge for tunneling
	default:
		return "🔵" // Blue circle for other types
	}
}