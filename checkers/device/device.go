package device

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
)

type DeviceChecker struct{}

type DeviceConfig struct {
	ShowVirtual bool
}

func NewDeviceChecker() checker.Checker {
	return &DeviceChecker{}
}

func (c *DeviceChecker) Name() string {
	return "device"
}

func (c *DeviceChecker) Description() string {
	return "Local device and network interface analysis"
}

func (c *DeviceChecker) Icon() string {
	return "🖥️"
}

func (c *DeviceChecker) DefaultConfig() checker.CheckerConfig {
	return DeviceConfig{
		ShowVirtual: false,
	}
}

func (c *DeviceChecker) RequiresRouter() bool {
	return false
}

func (c *DeviceChecker) DefaultEnabled() bool {
	return true
}

func (c *DeviceChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{}
}

func (c *DeviceChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	// Standalone checker - no router-based functionality
}

func (c *DeviceChecker) RunStandalone(config checker.CheckerConfig) {
	cfg := config.(DeviceConfig)
	checkDevice(cfg)
}

func (c *DeviceChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_device",
		Description: "Analyze local device network interfaces, DHCP configuration, and hardware information",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"show_virtual": map[string]interface{}{
					"type":        "boolean",
					"description": "Show virtual network interfaces (VPN tunnels, Docker bridges, etc.)",
					"default":     false,
				},
			},
			"required": []string{},
		},
	}
}

// isVirtualInterface checks if an interface is virtual/auto-generated
func isVirtualInterface(name string) bool {
	// Common virtual interface prefixes across different systems
	virtualPrefixes := []string{
		"utun",   // macOS VPN tunnels
		"awdl",   // macOS Apple Wireless Direct Link
		"llw",    // macOS Low latency WLAN interface
		"bridge", // Bridge interfaces
		"veth",   // Linux virtual ethernet (Docker)
		"docker", // Docker interfaces
		"virbr",  // Virtual bridge (libvirt)
		"vnet",   // Virtual network interfaces
		"tap",    // TAP interfaces
		"tun",    // TUN interfaces (generic)
		"gif",    // Generic tunnel interface
		"stf",    // 6to4 tunnel interface
		"anpi",   // macOS internal interfaces
		"ap",     // macOS access point interface
	}

	// Check if the interface starts with any virtual prefix
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

func checkDevice(cfg DeviceConfig) {
	fmt.Println("🖥️  Device/Interface Information")
	fmt.Println("==============================")

	// Get network interfaces
	interfaces := getNetworkInterfaces(cfg.ShowVirtual)
	if len(interfaces) > 0 {
		fmt.Printf("  📡 Network Interfaces (%d found):\n", len(interfaces))
		for _, iface := range interfaces {
			fmt.Printf("    %s\n", iface)
		}
		fmt.Println()
	}

	// Get DHCP information
	dhcpInfo := getDHCPInformation()
	if len(dhcpInfo) > 0 {
		fmt.Println("  🔧 DHCP/Network Configuration:")
		for _, info := range dhcpInfo {
			fmt.Printf("    %s\n", info)
		}
		fmt.Println()
	}

	// Get hardware information
	hwInfo := getHardwareInformation()
	if len(hwInfo) > 0 {
		fmt.Println("  💾 Hardware Information:")
		for _, info := range hwInfo {
			fmt.Printf("    %s\n", info)
		}
		fmt.Println()
	}

	if len(interfaces) == 0 && len(dhcpInfo) == 0 && len(hwInfo) == 0 {
		fmt.Println("  ℹ️  No device information available")
	}
}

// getNetworkInterfaces retrieves network interface information
func getNetworkInterfaces(showVirtual bool) []string {
	var interfaces []string

	// Get Go's view of network interfaces first
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			// Skip virtual interfaces unless showVirtual flag is set
			if !showVirtual && isVirtualInterface(iface.Name) {
				continue
			}
			var status string
			if iface.Flags&net.FlagUp != 0 {
				status = "UP"
			} else {
				status = "DOWN"
			}

			// Get addresses for this interface
			addrs, err := iface.Addrs()
			var addrStr string
			if err == nil && len(addrs) > 0 {
				var ips []string
				for _, addr := range addrs {
					ips = append(ips, addr.String())
				}
				addrStr = fmt.Sprintf(" [%s]", strings.Join(ips, ", "))
			}

			interfaces = append(interfaces, fmt.Sprintf("%s (%s) - %s %s%s",
				iface.Name, iface.HardwareAddr.String(), status,
				fmt.Sprintf("MTU:%d", iface.MTU), addrStr))
		}
	}

	// Try to get additional info from system commands
	sysInterfaces := getSystemInterfaces()
	if len(sysInterfaces) > 0 && len(interfaces) == 0 {
		interfaces = sysInterfaces
	}

	return interfaces
}

// getSystemInterfaces gets interface info from system commands
func getSystemInterfaces() []string {
	var interfaces []string

	// Try ifconfig first (most portable)
	cmd := exec.Command("ifconfig")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		var currentIface string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// New interface line
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				if strings.Contains(line, ":") {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						currentIface = strings.TrimSuffix(parts[0], ":")
					}
				}
			} else if currentIface != "" && strings.Contains(line, "inet") {
				// Add interface with basic info
				interfaces = append(interfaces, fmt.Sprintf("%s - %s", currentIface, line))
				currentIface = ""
			}
		}
	}

	// Try ip command on Linux if ifconfig failed
	if len(interfaces) == 0 {
		cmd = exec.Command("ip", "addr", "show")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, ": ") && (strings.Contains(line, "UP") || strings.Contains(line, "DOWN")) {
					interfaces = append(interfaces, line)
				}
			}
		}
	}

	return interfaces
}

// getDHCPInformation retrieves DHCP and network configuration info
func getDHCPInformation() []string {
	var info []string

	// Try to get DNS servers
	if dnsServers := getDNSServers(); len(dnsServers) > 0 {
		info = append(info, fmt.Sprintf("DNS Servers: %s", strings.Join(dnsServers, ", ")))
	}

	// Try to get default gateway
	if gateway := getDefaultGateway(); gateway != "" {
		info = append(info, fmt.Sprintf("Default Gateway: %s", gateway))
	}

	// Try macOS specific DHCP info
	cmd := exec.Command("ipconfig", "getpacket", "en0")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "server_identifier") ||
				strings.Contains(line, "lease_time") ||
				strings.Contains(line, "domain_name") {
				info = append(info, line)
			}
		}
	}

	// Try Linux DHCP info
	cmd = exec.Command("cat", "/var/lib/dhcp/dhclient.leases")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		info = append(info, "DHCP lease file found")
	}

	return info
}

// getDNSServers attempts to get DNS server information
func getDNSServers() []string {
	var servers []string

	// Try reading /etc/resolv.conf
	cmd := exec.Command("cat", "/etc/resolv.conf")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					servers = append(servers, parts[1])
				}
			}
		}
	}

	// Try macOS specific command
	if len(servers) == 0 {
		cmd = exec.Command("scutil", "--dns")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "nameserver") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						servers = append(servers, parts[2])
					}
				}
			}
		}
	}

	return servers
}

// getDefaultGateway attempts to get default gateway information
func getDefaultGateway() string {
	// Try route command
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "gateway:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					return parts[1]
				}
			}
		}
	}

	// Try Linux route command
	cmd = exec.Command("ip", "route", "show", "default")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "default via") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return parts[2]
				}
			}
		}
	}

	return ""
}

// getHardwareInformation retrieves basic hardware information
func getHardwareInformation() []string {
	var info []string

	// Try to get system information
	cmd := exec.Command("uname", "-a")
	output, err := cmd.Output()
	if err == nil {
		info = append(info, fmt.Sprintf("System: %s", strings.TrimSpace(string(output))))
	}

	// Try to get CPU information (Linux)
	cmd = exec.Command("cat", "/proc/cpuinfo")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "model name") {
				info = append(info, line)
				break
			}
		}
	}

	// Try macOS system profiler for basic hardware info
	cmd = exec.Command("system_profiler", "SPHardwareDataType", "-detailLevel", "mini")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Model Name") ||
				strings.Contains(line, "Processor") ||
				strings.Contains(line, "Memory") {
				info = append(info, line)
			}
		}
	}

	return info
}
