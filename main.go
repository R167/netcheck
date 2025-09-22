package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers"
	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/mcp"
	"github.com/R167/netcheck/starlink"
)

// Severity levels for security issues
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Common timeouts
const (
	HTTPTimeout   = 5 * time.Second
	PortTimeout   = 1 * time.Second // Reduced from 2s for faster scanning on restricted networks
	NATpmpTimeout = 3 * time.Second
)

// severityOrder defines the priority order for security issues
var severityOrder = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
}

type SecurityIssue struct {
	Severity    string
	Description string
	Details     string
}

type RouterInfo struct {
	IP            string
	Vendor        string
	Model         string
	SerialNumber  string
	ExternalIP    string
	WebInterface  bool
	DefaultCreds  bool
	OpenPorts     []int
	UPnPEnabled   bool
	NATpmpEnabled bool
	IPv6Enabled   bool
	MDNSEnabled   bool
	PortMappings  []PortMapping
	MDNSServices  []MDNSService
	Issues        []SecurityIssue
	Starlink      *starlink.StarLinkInfo
}

type PortMapping struct {
	ExternalPort int
	InternalIP   string
	InternalPort int
	Protocol     string
	Description  string
}

type UPnPDevice struct {
	DeviceType      string `xml:"device>deviceType"`
	FriendlyName    string `xml:"device>friendlyName"`
	Manufacturer    string `xml:"device>manufacturer"`
	ModelName       string `xml:"device>modelName"`
	ModelNumber     string `xml:"device>modelNumber"`
	SerialNumber    string `xml:"device>serialNumber"`
	PresentationURL string `xml:"device>presentationURL"`
}

type SSDPResponse struct {
	Location string
	Server   string
	USN      string
}

type MDNSService struct {
	Name    string
	Type    string
	Domain  string
	IP      string
	Port    int
	TXTData []string
}

var (
	// Test category flags
	allFlag      = flag.Bool("all", false, "Run all available tests")
	defaultFlag  = flag.Bool("default", false, "Run default test suite (same as no flags)")
	webFlag      = flag.Bool("web", false, "Test web interface and default credentials")
	portsFlag    = flag.Bool("ports", false, "Scan common management ports")
	upnpFlag     = flag.Bool("upnp", false, "Test UPnP services and port mappings")
	natpmpFlag   = flag.Bool("natpmp", false, "Test NAT-PMP services")
	ipv6Flag     = flag.Bool("ipv6", false, "Check IPv6 configuration")
	mdnsFlag     = flag.Bool("mdns", false, "Perform comprehensive mDNS service discovery")
	ssdpFlag     = flag.Bool("ssdp", false, "Discover SSDP services (DLNA, IoT devices)")
	apiFlag      = flag.Bool("api", false, "Check for exposed router APIs")
	starlinkFlag = flag.Bool("starlink", false, "Check for Starlink Dishy")
	routesFlag   = flag.Bool("routes", false, "Display routing information")
	deviceFlag   = flag.Bool("device", false, "Display interface/device information")
	externalFlag = flag.Bool("external", false, "Discover external IPv4/IPv6 addresses")
	proxyFlag    = flag.Bool("proxy", false, "Test proxy configuration (requires --external)")
	lldpFlag     = flag.Bool("lldp", false, "Link layer discovery and debugging")

	// Global configuration flags
	mcpFlag         = flag.Bool("mcp", false, "Run in MCP server mode (stdout)")
	timeoutFlag     = flag.Duration("timeout", 60*time.Second, "Maximum time to run all tests (e.g. 30s, 2m, 1h)")
	showVirtualFlag = flag.Bool("show-virtual", false, "Show virtual network interfaces (VPN tunnels, Docker bridges, etc.)")
	portTimeoutFlag = flag.Duration("port-timeout", PortTimeout, "Timeout for individual port scans (e.g. 500ms, 1s, 2s)")
)

func main() {
	flag.Parse()

	if *mcpFlag {
		runMCPMode()
		return
	}

	runCLIMode()
}

func runMCPMode() {
	registry := mcp.NewCheckerRegistry()

	registry.Register("check_web_interface", adaptWebCheck)
	registry.Register("scan_ports", adaptPortScan)

	if err := mcp.RunServer(registry); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func runCLIMode() {
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runNetcheck()
	}()

	select {
	case <-done:
	case <-ctx.Done():
		fmt.Printf("\n⏰ Timeout reached (%v) - stopping checks\n", *timeoutFlag)
		os.Exit(1)
	}
}

func runNetcheck() {
	fmt.Println("🔍 Network Gateway Security Checker")
	fmt.Println("====================================")

	// Determine which checks to run
	selectedChecks := getSelectedChecks()

	// Run standalone checks first (routes, device, external, lldp - not migrated yet)
	for _, check := range selectedChecks {
		if !check.RequiresRouter {
			check.StandaloneFunc()
		}
	}

	// Check if we need to run router checks
	needsRouter := false
	for _, check := range selectedChecks {
		if check.RequiresRouter {
			needsRouter = true
			break
		}
	}

	if !needsRouter {
		return
	}

	// Get gateway for router-based checks
	gatewayIP := getGatewayIP()
	if gatewayIP == "" {
		fmt.Println("❌ Could not determine gateway IP")
		os.Exit(1)
	}

	fmt.Printf("🌐 Gateway IP: %s\n\n", gatewayIP)

	router := &RouterInfo{
		IP:           gatewayIP,
		OpenPorts:    []int{},
		Issues:       []SecurityIssue{},
		MDNSServices: []MDNSService{},
	}

	// Run router-based checks
	for _, check := range selectedChecks {
		if check.RequiresRouter {
			check.RunFunc(router)
		}
	}

	generateReport(router)
}

// getSelectedChecks determines which checks should be run based on flags
func getSelectedChecks() []Check {
	var selected []Check

	// Check if no specific flags were set (default mode)
	noFlagsSet := true
	for _, check := range checks {
		if *check.Flag {
			noFlagsSet = false
			break
		}
	}
	if !noFlagsSet {
		noFlagsSet = *defaultFlag
	}

	// If --all is set, run everything
	if *allFlag {
		return checks
	}

	// Otherwise, run selected checks or default set
	for _, check := range checks {
		shouldRun := false

		if *check.Flag {
			shouldRun = true
		} else if (noFlagsSet || *defaultFlag) && check.DefaultEnabled {
			shouldRun = true
		}

		if shouldRun {
			selected = append(selected, check)
		}
	}

	return selected
}

func getGatewayIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}

	parts[3] = "1"
	return strings.Join(parts, ".")
}

func toCommonRouter(r *RouterInfo) *common.RouterInfo {
	cr := &common.RouterInfo{
		IP:            r.IP,
		Vendor:        r.Vendor,
		Model:         r.Model,
		SerialNumber:  r.SerialNumber,
		ExternalIP:    r.ExternalIP,
		WebInterface:  r.WebInterface,
		DefaultCreds:  r.DefaultCreds,
		OpenPorts:     r.OpenPorts,
		UPnPEnabled:   r.UPnPEnabled,
		NATpmpEnabled: r.NATpmpEnabled,
		IPv6Enabled:   r.IPv6Enabled,
		MDNSEnabled:   r.MDNSEnabled,
		PortMappings:  make([]common.PortMapping, 0),
		MDNSServices:  make([]common.MDNSService, 0),
		Issues:        make([]common.SecurityIssue, 0),
		Starlink:      r.Starlink,
	}
	for _, pm := range r.PortMappings {
		cr.PortMappings = append(cr.PortMappings, common.PortMapping{
			ExternalPort: pm.ExternalPort,
			InternalIP:   pm.InternalIP,
			InternalPort: pm.InternalPort,
			Protocol:     pm.Protocol,
			Description:  pm.Description,
		})
	}
	for _, ms := range r.MDNSServices {
		cr.MDNSServices = append(cr.MDNSServices, common.MDNSService{
			Name:    ms.Name,
			Type:    ms.Type,
			Domain:  ms.Domain,
			IP:      ms.IP,
			Port:    ms.Port,
			TXTData: ms.TXTData,
		})
	}
	for _, iss := range r.Issues {
		cr.Issues = append(cr.Issues, common.SecurityIssue{
			Severity:    iss.Severity,
			Description: iss.Description,
			Details:     iss.Details,
		})
	}
	return cr
}

func fromCommonRouter(r *RouterInfo, cr *common.RouterInfo) {
	r.Vendor = cr.Vendor
	r.Model = cr.Model
	r.SerialNumber = cr.SerialNumber
	r.WebInterface = cr.WebInterface
	r.DefaultCreds = cr.DefaultCreds
	r.OpenPorts = cr.OpenPorts
	r.UPnPEnabled = cr.UPnPEnabled
	r.NATpmpEnabled = cr.NATpmpEnabled
	r.IPv6Enabled = cr.IPv6Enabled
	r.MDNSEnabled = cr.MDNSEnabled

	r.PortMappings = make([]PortMapping, 0)
	for _, pm := range cr.PortMappings {
		r.PortMappings = append(r.PortMappings, PortMapping{
			ExternalPort: pm.ExternalPort,
			InternalIP:   pm.InternalIP,
			InternalPort: pm.InternalPort,
			Protocol:     pm.Protocol,
			Description:  pm.Description,
		})
	}

	r.MDNSServices = make([]MDNSService, 0)
	for _, ms := range cr.MDNSServices {
		r.MDNSServices = append(r.MDNSServices, MDNSService{
			Name:    ms.Name,
			Type:    ms.Type,
			Domain:  ms.Domain,
			IP:      ms.IP,
			Port:    ms.Port,
			TXTData: ms.TXTData,
		})
	}

	r.Issues = make([]SecurityIssue, 0)
	for _, iss := range cr.Issues {
		r.Issues = append(r.Issues, SecurityIssue{
			Severity:    iss.Severity,
			Description: iss.Description,
			Details:     iss.Details,
		})
	}
}

func generateReport(router *RouterInfo) {
	fmt.Println("\n📊 Security Assessment Report")
	fmt.Println("=============================")

	if router.Vendor != "" {
		fmt.Printf("Vendor: %s\n", strings.Title(router.Vendor))
	}
	if router.Model != "" {
		fmt.Printf("Model: %s\n", router.Model)
	}
	if router.SerialNumber != "" {
		fmt.Printf("Serial: %s\n", router.SerialNumber)
	}
	fmt.Printf("Web Interface: %t\n", router.WebInterface)
	fmt.Printf("UPnP Enabled: %t\n", router.UPnPEnabled)
	fmt.Printf("NAT-PMP Enabled: %t\n", router.NATpmpEnabled)
	fmt.Printf("IPv6 Enabled: %t\n", router.IPv6Enabled)
	fmt.Printf("mDNS Enabled: %t\n", router.MDNSEnabled)
	if len(router.PortMappings) > 0 {
		fmt.Printf("Port Mappings: %d active\n", len(router.PortMappings))
	}
	if len(router.MDNSServices) > 0 {
		fmt.Printf("mDNS Services: %d discovered\n", len(router.MDNSServices))
	}
	fmt.Printf("Open Ports: %v\n", router.OpenPorts)
	fmt.Printf("Issues Found: %d\n\n", len(router.Issues))

	// Display detailed port mappings if any exist
	if len(router.PortMappings) > 0 {
		fmt.Println("\n🔓 Active Port Mappings:")
		for i, mapping := range router.PortMappings {
			description := mapping.Description
			if description == "" {
				description = "No description"
			}
			fmt.Printf("%d. External %s:%d → Internal %s:%d (%s)\n",
				i+1, "*", mapping.ExternalPort, mapping.InternalIP, mapping.InternalPort, description)
		}
		fmt.Println()
	}

	// Display discovered mDNS services if any exist
	if len(router.MDNSServices) > 0 {
		fmt.Println("\n📡 Discovered mDNS Services:")
		for i, service := range router.MDNSServices {
			if service.IP != "" && service.Port > 0 {
				fmt.Printf("%d. %s (%s) at %s:%d\n",
					i+1, service.Name, service.Type, service.IP, service.Port)
			} else {
				fmt.Printf("%d. %s (%s)\n",
					i+1, service.Name, service.Type)
			}
		}
		fmt.Println()
	}

	// Display Starlink information if detected
	if router.Starlink != nil && router.Starlink.Accessible {
		fmt.Print(starlink.FormatStarlinkReport(router.Starlink))
	}

	if len(router.Issues) == 0 {
		fmt.Println("✅ No major security issues detected!")
		return
	}

	sort.Slice(router.Issues, func(i, j int) bool {
		return severityOrder[router.Issues[i].Severity] < severityOrder[router.Issues[j].Severity]
	})

	fmt.Println("🚨 Security Issues:")
	for i, issue := range router.Issues {
		emoji := getEmojiForSeverity(issue.Severity)
		fmt.Printf("%d. %s [%s] %s\n", i+1, emoji, issue.Severity, issue.Description)
		fmt.Printf("   %s\n\n", issue.Details)
	}

	printRecommendations(router)
}

func getEmojiForSeverity(severity string) string {
	switch severity {
	case SeverityCritical:
		return "🚨"
	case SeverityHigh:
		return "⚠️"
	case SeverityMedium:
		return "🔶"
	case SeverityLow:
		return "ℹ️"
	default:
		return "⚠️"
	}
}

func printRecommendations(router *RouterInfo) {
	fmt.Println("💡 Recommendations:")
	fmt.Println("• Change all default passwords immediately")
	fmt.Println("• Disable unnecessary services and ports")
	fmt.Println("• Enable firewall if available")
	fmt.Println("• Check for firmware updates regularly")
	fmt.Println("• Consider changing default admin interface port")
	if router.UPnPEnabled {
		fmt.Println("• Consider disabling UPnP if not needed")
	}
	if router.IPv6Enabled {
		fmt.Println("• Review IPv6 firewall configuration")
	}
}

// Check represents a security check or information gathering function
type Check struct {
	Name           string
	Description    string
	Icon           string
	Flag           *bool
	RunFunc        func(*RouterInfo)
	StandaloneFunc func()
	RequiresRouter bool
	DefaultEnabled bool
}

// buildChecksRegistry creates the checks array from checker packages
func buildChecksRegistry() []Check {
	var checks []Check

	// Map of flag names to flag pointers
	flagMap := map[string]*bool{
		"web":      webFlag,
		"ports":    portsFlag,
		"upnp":     upnpFlag,
		"natpmp":   natpmpFlag,
		"ipv6":     ipv6Flag,
		"mdns":     mdnsFlag,
		"ssdp":     ssdpFlag,
		"api":      apiFlag,
		"starlink": starlinkFlag,
		"routes":   routesFlag,
		"device":   deviceFlag,
		"external": externalFlag,
		"lldp":     lldpFlag,
	}

	// Build checks from the checker registry
	for _, checker := range checkers.AllCheckers() {
		checkerName := checker.Name()
		checkerConfig := checker.DefaultConfig()

		var runFunc func(*RouterInfo)
		var standaloneFunc func()

		if checker.RequiresRouter() {
			runFunc = func(r *RouterInfo) {
				cr := toCommonRouter(r)
				checkers.RunChecker(checkerName, checkerConfig, cr)
				fromCommonRouter(r, cr)
			}
		} else {
			standaloneFunc = func() {
				checkers.RunStandaloneChecker(checkerName, checkerConfig)
			}
		}

		checks = append(checks, Check{
			Name:           checkerName,
			Description:    checker.Description(),
			Icon:           checker.Icon(),
			Flag:           flagMap[checkerName],
			RunFunc:        runFunc,
			StandaloneFunc: standaloneFunc,
			RequiresRouter: checker.RequiresRouter(),
			DefaultEnabled: checker.DefaultEnabled(),
		})
	}

	return checks
}

// Global check registry - built dynamically from checker packages
var checks = buildChecksRegistry()
