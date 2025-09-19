package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

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
	PortTimeout   = 1 * time.Second  // Reduced from 2s for faster scanning on restricted networks
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
	DeviceType         string `xml:"device>deviceType"`
	FriendlyName       string `xml:"device>friendlyName"`
	Manufacturer       string `xml:"device>manufacturer"`
	ModelName          string `xml:"device>modelName"`
	ModelNumber        string `xml:"device>modelNumber"`
	SerialNumber       string `xml:"device>serialNumber"`
	PresentationURL    string `xml:"device>presentationURL"`
}

type SSDPResponse struct {
	Location string
	Server   string
	USN      string
}

type MDNSService struct {
	Name     string
	Type     string
	Domain   string
	IP       string
	Port     int
	TXTData  []string
}


var (
	// Test category flags
	allFlag        = flag.Bool("all", false, "Run all available tests")
	defaultFlag    = flag.Bool("default", false, "Run default test suite (same as no flags)")
	webFlag        = flag.Bool("web", false, "Test web interface and default credentials")
	portsFlag      = flag.Bool("ports", false, "Scan common management ports")
	upnpFlag       = flag.Bool("upnp", false, "Test UPnP services and port mappings")
	natpmpFlag     = flag.Bool("natpmp", false, "Test NAT-PMP services")
	ipv6Flag       = flag.Bool("ipv6", false, "Check IPv6 configuration")
	mdnsFlag       = flag.Bool("mdns", false, "Perform comprehensive mDNS service discovery")
	apiFlag        = flag.Bool("api", false, "Check for exposed router APIs")
	starlinkFlag   = flag.Bool("starlink", false, "Check for Starlink Dishy")
	routesFlag     = flag.Bool("routes", false, "Display routing information")
	deviceFlag     = flag.Bool("device", false, "Display interface/device information")
	externalFlag   = flag.Bool("external", false, "Discover external IPv4/IPv6 addresses")
	proxyFlag      = flag.Bool("proxy", false, "Test proxy configuration (requires --external)")
	lldpFlag       = flag.Bool("lldp", false, "Link layer discovery and debugging")

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

	// Run standalone checks first
	standaloneRan := false
	for _, check := range selectedChecks {
		if !check.RequiresRouter {
			check.StandaloneFunc()
			standaloneRan = true
		}
	}

	// If only standalone checks were requested, exit
	onlyStandalone := true
	for _, check := range selectedChecks {
		if check.RequiresRouter {
			onlyStandalone = false
			break
		}
	}
	if standaloneRan && onlyStandalone {
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

func checkWebInterface(router *RouterInfo) {
	fmt.Println("🔍 Checking web interface...")

	client := &http.Client{
		Timeout: HTTPTimeout,
	}

	urls := []string{
		fmt.Sprintf("http://%s", router.IP),
		fmt.Sprintf("https://%s", router.IP),
		fmt.Sprintf("http://%s:8080", router.IP),
		fmt.Sprintf("https://%s:8443", router.IP),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		router.WebInterface = true
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		content := string(body)
		detectVendor(router, content)
		checkDefaultPage(router, content, url)
		checkDefaultCredentials(router, url)
		break
	}

	if !router.WebInterface {
		fmt.Println("  ℹ️  No web interface detected")
	}
}

func detectVendor(router *RouterInfo, content string) {
	for vendor, pattern := range vendorPatterns {
		if pattern.MatchString(content) {
			router.Vendor = vendor
			fmt.Printf("  📱 Detected vendor: %s\n", strings.Title(vendor))
			break
		}
	}

	if matches := titlePattern.FindStringSubmatch(content); len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if router.Vendor == "" && title != "" {
			fmt.Printf("  📄 Page title: %s\n", title)
		}
	}
}

func checkDefaultPage(router *RouterInfo, content, url string) {
	contentLower := strings.ToLower(content)
	for _, indicator := range defaultPageIndicators {
		if strings.Contains(contentLower, indicator) {
			router.Issues = append(router.Issues, SecurityIssue{
				Severity:    SeverityHigh,
				Description: "Default setup page detected",
				Details:     fmt.Sprintf("Router appears to be using default configuration at %s", url),
			})
			fmt.Printf("  ⚠️  Default setup page detected\n")
			return
		}
	}
}

func checkDefaultCredentials(router *RouterInfo, baseURL string) {
	if router.Vendor == "" {
		return
	}

	creds, exists := defaultCredentials[router.Vendor]
	if !exists {
		return
	}

	fmt.Printf("  🔐 Testing default credentials for %s...\n", router.Vendor)

	client := &http.Client{
		Timeout: HTTPTimeout,
	}

	for _, cred := range creds {
		if testCredentials(client, baseURL, cred.Username, cred.Password) {
			router.DefaultCreds = true
			router.Issues = append(router.Issues, SecurityIssue{
				Severity:    SeverityCritical,
				Description: "Default credentials are active",
				Details:     fmt.Sprintf("Username: '%s', Password: '%s'", cred.Username, cred.Password),
			})
			fmt.Printf("  🚨 Default credentials work: %s/%s\n", cred.Username, cred.Password)
			return
		}
	}

	fmt.Printf("  ✅ Default credentials not working\n")
}

func testCredentials(client *http.Client, baseURL, username, password string) bool {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// Common management ports and their security implications
var managementPorts = map[int]SecurityIssue{
	22: {
		Severity:    SeverityMedium,
		Description: "SSH service exposed",
		Details:     "SSH is accessible from the network. Ensure strong authentication is configured.",
	},
	23: {
		Severity:    SeverityHigh,
		Description: "Telnet service exposed",
		Details:     "Telnet transmits data in plain text. Consider disabling if not needed.",
	},
	161: {
		Severity:    SeverityMedium,
		Description: "SNMP service exposed",
		Details:     "SNMP can expose device information. Ensure community strings are changed from defaults.",
	},
}

func scanCommonPorts(router *RouterInfo) {
	fmt.Println("\n🔍 Scanning common management ports...")

	commonPorts := []int{22, 23, 80, 443, 8080, 8443, 21, 53, 161, 8291}

	for _, port := range commonPorts {
		if isPortOpen(router.IP, port) {
			router.OpenPorts = append(router.OpenPorts, port)
			fmt.Printf("  ✅ Port %d open\n", port)

			// Add security issue if this port has known risks
			if issue, exists := managementPorts[port]; exists {
				router.Issues = append(router.Issues, issue)
			}
		}
	}

	if len(router.OpenPorts) == 0 {
		fmt.Println("  ℹ️  No common management ports detected")
	}
}

func isPortOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), *portTimeoutFlag)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkNATpmp(router *RouterInfo) {
	fmt.Println("\n🔍 Checking NAT-PMP...")

	// Send NAT-PMP external address request
	if sendNATpmpRequest(router.IP) {
		router.NATpmpEnabled = true
		fmt.Println("  📡 NAT-PMP service detected")

		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    SeverityMedium,
			Description: "NAT-PMP service is enabled",
			Details:     "NAT-PMP allows automatic port mapping. Ensure it's properly secured.",
		})
	} else {
		fmt.Println("  ✅ No NAT-PMP service detected")
	}
}

func sendNATpmpRequest(gatewayIP string) bool {
	conn, err := net.Dial("udp", gatewayIP+":5351")
	if err != nil {
		return false
	}
	defer conn.Close()

	// NAT-PMP external address request: version=0, opcode=0
	request := []byte{0, 0}

	conn.SetDeadline(time.Now().Add(NATpmpTimeout))
	_, err = conn.Write(request)
	if err != nil {
		return false
	}

	response := make([]byte, 12)
	n, err := conn.Read(response)
	if err != nil || n < 8 {
		return false
	}

	// Check if response is valid NAT-PMP response
	// Version should be 0, opcode should be 128 (0x80 + 0), result should be 0 for success
	return response[0] == 0 && response[1] == 128 && response[2] == 0 && response[3] == 0
}


// APIEndpoint represents a router API endpoint with security implications
type APIEndpoint struct {
	Path        string
	Description string
	Severity    string
}

// Common router API endpoints
var routerAPIEndpoints = []APIEndpoint{
	{"/api/", "Generic API endpoint", SeverityMedium},
	{"/cgi-bin/", "CGI scripts", SeverityHigh},
	{"/status.xml", "Status XML", SeverityLow},
	{"/info.html", "Device info", SeverityLow},
	{"/system.xml", "System XML", SeverityMedium},
	{"/wan.xml", "WAN configuration", SeverityMedium},
	{"/wireless.xml", "Wireless config", SeverityMedium},
	{"/tr069", "TR-069 management", SeverityHigh},
	{"/remote/", "Remote management", SeverityHigh},
	{"/goform/", "Form handlers", SeverityMedium},
	{"/boaform/", "BOA form handlers", SeverityMedium},
}

func checkRouterAPIs(router *RouterInfo) {
	fmt.Println("\n🔍 Checking for exposed APIs and services...")

	client := &http.Client{Timeout: HTTPTimeout}

	foundAPIs := 0
	for _, endpoint := range routerAPIEndpoints {
		url := fmt.Sprintf("http://%s%s", router.IP, endpoint.Path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			foundAPIs++
			fmt.Printf("  🔍 Found: %s (%s)\n", endpoint.Path, endpoint.Description)

			if endpoint.Severity == SeverityHigh {
				router.Issues = append(router.Issues, SecurityIssue{
					Severity:    endpoint.Severity,
					Description: fmt.Sprintf("Exposed %s", endpoint.Description),
					Details:     fmt.Sprintf("Endpoint %s is accessible and may expose sensitive functionality", endpoint.Path),
				})
			}
		}
	}

	if foundAPIs == 0 {
		fmt.Println("  ✅ No suspicious API endpoints detected")
	}

	// Check for WPS (WiFi Protected Setup)
	checkWPS(router)
}

// Common WPS-related paths
var wpsPaths = []string{
	"/wps.html",
	"/wireless_wps.html",
	"/wps_setup.html",
	"/advanced_wireless_wps.html",
}

func checkWPS(router *RouterInfo) {
	fmt.Println("\n🔍 Checking WPS configuration...")

	client := &http.Client{Timeout: HTTPTimeout}

	for _, path := range wpsPaths {
		url := fmt.Sprintf("http://%s%s", router.IP, path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			content := strings.ToLower(string(body))
			if strings.Contains(content, "wps") && strings.Contains(content, "enabled") {
				fmt.Println("  ⚠️  WPS may be enabled")

				router.Issues = append(router.Issues, SecurityIssue{
					Severity:    SeverityMedium,
					Description: "WPS (WiFi Protected Setup) may be enabled",
					Details:     "WPS has known security vulnerabilities and should be disabled if not needed.",
				})
				return
			}
		}
	}

	fmt.Println("  ℹ️  WPS configuration not accessible")
}

func checkStarlink(router *RouterInfo) {
	fmt.Println("🛰️  Checking for Starlink Dishy...")

	starlinkInfo := starlink.CheckStarlink()
	router.Starlink = starlinkInfo

	if starlinkInfo.Accessible {
		fmt.Println("  📡 Starlink Dishy detected and accessible")

		if starlinkInfo.DeviceInfo != nil {
			fmt.Printf("  🔧 Hardware: %s\n", starlinkInfo.DeviceInfo.HardwareVersion)
			fmt.Printf("  💾 Software: %s\n", starlinkInfo.DeviceInfo.SoftwareVersion)
		}

		if len(starlinkInfo.SecurityIssues) > 0 {
			fmt.Printf("  ⚠️  Found %d security issue(s)\n", len(starlinkInfo.SecurityIssues))

			// Add Starlink security issues to router issues with proper format conversion
			for _, issue := range starlinkInfo.SecurityIssues {
				router.Issues = append(router.Issues, SecurityIssue{
					Severity:    issue.Severity,
					Description: issue.Title,
					Details:     issue.Description + ". " + issue.Impact + " " + issue.Remediation,
				})
			}
		} else {
			fmt.Println("  ✅ No security issues detected")
		}
	} else {
		fmt.Println("  ℹ️  No Starlink Dishy detected on network")
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
	Name         string
	Description  string
	Icon         string
	Flag         *bool
	RunFunc      func(*RouterInfo)
	StandaloneFunc func()
	RequiresRouter bool
	DefaultEnabled bool
}

// Global check registry
var checks = []Check{
	{
		Name:           "web",
		Description:    "Web interface and default credentials",
		Icon:           "🔍",
		Flag:           webFlag,
		RunFunc:        checkWebInterface,
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "ports",
		Description:    "Common management ports",
		Icon:           "🔍",
		Flag:           portsFlag,
		RunFunc:        func(r *RouterInfo) { scanCommonPorts(r) },
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "upnp",
		Description:    "UPnP services and port mappings",
		Icon:           "🔍",
		Flag:           upnpFlag,
		RunFunc:        checkUPnP,
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "natpmp",
		Description:    "NAT-PMP services",
		Icon:           "🔍",
		Flag:           natpmpFlag,
		RunFunc:        checkNATpmp,
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "ipv6",
		Description:    "IPv6 configuration",
		Icon:           "🔍",
		Flag:           ipv6Flag,
		RunFunc:        checkIPv6,
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "mdns",
		Description:    "mDNS service discovery",
		Icon:           "📡",
		Flag:           mdnsFlag,
		RunFunc:        checkMDNS,
		RequiresRouter: true,
		DefaultEnabled: false,
	},
	{
		Name:           "api",
		Description:    "Router APIs and services",
		Icon:           "🔍",
		Flag:           apiFlag,
		RunFunc:        checkRouterAPIs,
		RequiresRouter: true,
		DefaultEnabled: true,
	},
	{
		Name:           "starlink",
		Description:    "Starlink Dishy detection",
		Icon:           "🛰️",
		Flag:           starlinkFlag,
		RunFunc:        checkStarlink,
		RequiresRouter: true,
		DefaultEnabled: false,
	},
	{
		Name:           "routes",
		Description:    "Routing information",
		Icon:           "📍",
		Flag:           routesFlag,
		StandaloneFunc: checkRoutes,
		RequiresRouter: false,
		DefaultEnabled: false,
	},
	{
		Name:           "device",
		Description:    "Interface/device information",
		Icon:           "🖥️",
		Flag:           deviceFlag,
		StandaloneFunc: checkDevice,
		RequiresRouter: false,
		DefaultEnabled: false,
	},
	{
		Name:           "external",
		Description:    "External address discovery",
		Icon:           "🌍",
		Flag:           externalFlag,
		StandaloneFunc: checkExternal,
		RequiresRouter: false,
		DefaultEnabled: false,
	},
	{
		Name:           "lldp",
		Description:    "Link layer discovery",
		Icon:           "🔗",
		Flag:           lldpFlag,
		StandaloneFunc: checkLLDP,
		RequiresRouter: false,
		DefaultEnabled: false,
	},
}








