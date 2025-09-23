package lldp

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type LLDPChecker struct{}

type LLDPConfig struct{}

// LLDP constants
const (
	// LLDP multicast address
	LLDPMulticastAddr = "01:80:c2:00:00:0e"
	// LLDP EtherType
	LLDPEtherType = 0x88cc
)

// LLDPNeighbor represents an LLDP neighbor device
type LLDPNeighbor struct {
	ChassisID    string
	PortID       string
	SystemName   string
	SystemDesc   string
	Capabilities []string
	ManagementIP string
	Interface    string
}

func NewLLDPChecker() checker.Checker {
	return &LLDPChecker{}
}

func (c *LLDPChecker) Name() string {
	return "lldp"
}

func (c *LLDPChecker) Description() string {
	return "Link Layer Discovery Protocol neighbor discovery"
}

func (c *LLDPChecker) Icon() string {
	return "🔗"
}

func (c *LLDPChecker) DefaultConfig() checker.CheckerConfig {
	return LLDPConfig{}
}

func (c *LLDPChecker) RequiresRouter() bool {
	return false
}

func (c *LLDPChecker) DefaultEnabled() bool {
	return true
}

func (c *LLDPChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{}
}

func (c *LLDPChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	// Standalone checker - no router-based functionality
}

func (c *LLDPChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
	checkLLDP(out)
}

func (c *LLDPChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_lldp",
		Description: "Discover LLDP neighbors and analyze network topology information disclosure",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
			"required":   []string{},
		},
	}
}

func checkLLDP(out output.Output) {
	fmt.Println("🔗 Link Layer Discovery Protocol")
	fmt.Println("===============================")

	// Check if LLDP is supported/enabled on the system
	if !isLLDPAvailable() {
		fmt.Println("  ℹ️  LLDP not available on this system")
		fmt.Println("  💡 LLDP requires:")
		fmt.Println("     • Linux: lldpctl utility (install lldpd package)")
		fmt.Println("     • macOS: Network discovery tools or third-party LLDP clients")
		fmt.Println("     • Admin privileges for raw socket access")
		return
	}

	// Attempt to discover LLDP neighbors
	neighbors := discoverLLDPNeighbors()

	if len(neighbors) > 0 {
		fmt.Printf("  📡 Found %d LLDP neighbors:\n", len(neighbors))
		for i, neighbor := range neighbors {
			fmt.Printf("  \n  🖥️  Neighbor %d:\n", i+1)
			if neighbor.SystemName != "" {
				fmt.Printf("    System Name: %s\n", neighbor.SystemName)
			}
			if neighbor.SystemDesc != "" {
				fmt.Printf("    Description: %s\n", neighbor.SystemDesc)
			}
			if neighbor.ChassisID != "" {
				fmt.Printf("    Chassis ID: %s\n", neighbor.ChassisID)
			}
			if neighbor.PortID != "" {
				fmt.Printf("    Port ID: %s\n", neighbor.PortID)
			}
			if neighbor.ManagementIP != "" {
				fmt.Printf("    Management IP: %s\n", neighbor.ManagementIP)
			}
			if neighbor.Interface != "" {
				fmt.Printf("    Local Interface: %s\n", neighbor.Interface)
			}
			if len(neighbor.Capabilities) > 0 {
				fmt.Printf("    Capabilities: %s\n", strings.Join(neighbor.Capabilities, ", "))
			}
		}

		// Security assessment
		assessLLDPSecurity(neighbors)
	} else {
		fmt.Println("  ✅ No LLDP neighbors discovered")
		fmt.Println("  ℹ️  This could mean:")
		fmt.Println("     • Network devices don't support LLDP")
		fmt.Println("     • LLDP is disabled on network equipment")
		fmt.Println("     • No directly connected managed devices")
	}
}

// isLLDPAvailable checks if LLDP tools are available on the system
func isLLDPAvailable() bool {
	// Check for lldpctl (Linux)
	if _, err := exec.LookPath("lldpctl"); err == nil {
		return true
	}

	// Check for lldpcli (alternative Linux tool)
	if _, err := exec.LookPath("lldpcli"); err == nil {
		return true
	}

	// On macOS, we can try to use tcpdump or other network tools
	// For now, return false as we don't have a reliable cross-platform solution
	return false
}

// discoverLLDPNeighbors attempts to discover LLDP neighbors using available tools
func discoverLLDPNeighbors() []LLDPNeighbor {
	var neighbors []LLDPNeighbor

	// Try using lldpctl first
	if neighbors = getLLDPFromLldpctl(); len(neighbors) > 0 {
		return neighbors
	}

	// Try using lldpcli
	if neighbors = getLLDPFromLldpcli(); len(neighbors) > 0 {
		return neighbors
	}

	// Try passive network monitoring approach
	if neighbors = getLLDPFromNetworkCapture(); len(neighbors) > 0 {
		return neighbors
	}

	return neighbors
}

// getLLDPFromLldpctl uses lldpctl command to get LLDP information
func getLLDPFromLldpctl() []LLDPNeighbor {
	var neighbors []LLDPNeighbor

	cmd := exec.Command("lldpctl", "-f", "keyvalue")
	output, err := cmd.Output()
	if err != nil {
		return neighbors
	}

	// Parse lldpctl keyvalue output
	currentNeighbor := LLDPNeighbor{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Parse different LLDP fields
		if strings.Contains(key, ".chassis.name") {
			currentNeighbor.SystemName = value
		} else if strings.Contains(key, ".chassis.descr") {
			currentNeighbor.SystemDesc = value
		} else if strings.Contains(key, ".chassis.id") {
			currentNeighbor.ChassisID = value
		} else if strings.Contains(key, ".port.id") {
			currentNeighbor.PortID = value
		} else if strings.Contains(key, ".mgmt-ip") {
			currentNeighbor.ManagementIP = value
		} else if strings.Contains(key, "lldp.") && strings.Contains(key, ".interface") {
			// Extract interface name from key
			keyParts := strings.Split(key, ".")
			if len(keyParts) > 1 {
				currentNeighbor.Interface = keyParts[1]
			}
		}

		// When we encounter a new interface section, save the current neighbor
		if strings.HasPrefix(key, "lldp.") && strings.HasSuffix(key, ".interface") {
			if currentNeighbor.SystemName != "" || currentNeighbor.ChassisID != "" {
				neighbors = append(neighbors, currentNeighbor)
			}
			currentNeighbor = LLDPNeighbor{}
		}
	}

	// Add the last neighbor if it has data
	if currentNeighbor.SystemName != "" || currentNeighbor.ChassisID != "" {
		neighbors = append(neighbors, currentNeighbor)
	}

	return neighbors
}

// getLLDPFromLldpcli uses lldpcli command to get LLDP information
func getLLDPFromLldpcli() []LLDPNeighbor {
	var neighbors []LLDPNeighbor

	cmd := exec.Command("lldpcli", "show", "neighbors", "details")
	output, err := cmd.Output()
	if err != nil {
		return neighbors
	}

	// Parse lldpcli output (more human-readable format)
	lines := strings.Split(string(output), "\n")
	currentNeighbor := LLDPNeighbor{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for key patterns in lldpcli output
		if strings.Contains(line, "SysName:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNeighbor.SystemName = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "SysDescr:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNeighbor.SystemDesc = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "ChassisID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNeighbor.ChassisID = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "PortID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNeighbor.PortID = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "MgmtIP:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentNeighbor.ManagementIP = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Interface:") || strings.Contains(line, "via:") {
			// End of neighbor entry, save it
			if currentNeighbor.SystemName != "" || currentNeighbor.ChassisID != "" {
				neighbors = append(neighbors, currentNeighbor)
			}
			currentNeighbor = LLDPNeighbor{}
		}
	}

	// Add the last neighbor if it has data
	if currentNeighbor.SystemName != "" || currentNeighbor.ChassisID != "" {
		neighbors = append(neighbors, currentNeighbor)
	}

	return neighbors
}

// getLLDPFromNetworkCapture attempts to capture LLDP frames from the network
func getLLDPFromNetworkCapture() []LLDPNeighbor {
	// This is a placeholder for raw socket LLDP capture
	// Implementation would require:
	// 1. Raw socket creation with appropriate privileges
	// 2. LLDP frame parsing (802.1AB standard)
	// 3. TLV (Type-Length-Value) decoding
	// 4. Timeout handling for passive listening

	// For now, we'll attempt a simplified approach using tcpdump if available
	return getLLDPFromTcpdump()
}

// getLLDPFromTcpdump attempts to use tcpdump to capture LLDP frames
func getLLDPFromTcpdump() []LLDPNeighbor {
	var neighbors []LLDPNeighbor

	// Check if tcpdump is available
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return neighbors
	}

	// Run tcpdump for a short period to capture LLDP frames
	cmd := exec.Command("tcpdump", "-i", "any", "-c", "10", "-n", "-q", "ether", "proto", "0x88cc")
	cmd.Stdout = nil // We don't want to process tcpdump output in this basic implementation

	// Set a timeout
	go func() {
		time.Sleep(5 * time.Second)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// For now, just try to run tcpdump and see if it finds anything
	err := cmd.Run()
	if err == nil {
		// If tcpdump ran successfully, it means LLDP traffic might be present
		// But we're not parsing the actual frames in this basic implementation
		neighbors = append(neighbors, LLDPNeighbor{
			SystemName: "Unknown LLDP Device",
			SystemDesc: "Detected via network capture (details not parsed)",
			Interface:  "Multiple interfaces possible",
		})
	}

	return neighbors
}

// assessLLDPSecurity performs security assessment of discovered LLDP neighbors
func assessLLDPSecurity(neighbors []LLDPNeighbor) {
	fmt.Println("\n  🛡️  Security Assessment:")

	if len(neighbors) > 0 {
		fmt.Printf("  ⚠️  Information Disclosure: LLDP reveals network topology\n")
		fmt.Printf("      • %d network devices are advertising their presence\n", len(neighbors))
		fmt.Printf("      • Device names, capabilities, and management IPs are exposed\n")
		fmt.Printf("      • This information aids network reconnaissance\n")

		// Check for management IPs
		mgmtIPs := 0
		for _, neighbor := range neighbors {
			if neighbor.ManagementIP != "" {
				mgmtIPs++
			}
		}

		if mgmtIPs > 0 {
			fmt.Printf("  🔴 %d devices expose management IP addresses\n", mgmtIPs)
			fmt.Printf("      • These IPs may provide administrative access\n")
			fmt.Printf("      • Consider network segmentation for management traffic\n")
		}

		// General recommendations
		fmt.Println("\n  💡 Recommendations:")
		fmt.Println("     • Disable LLDP on untrusted network segments")
		fmt.Println("     • Use LLDP-MED for VoIP devices only when necessary")
		fmt.Println("     • Monitor LLDP advertisements for unauthorized devices")
		fmt.Println("     • Implement network access control (802.1X)")
	}
}
