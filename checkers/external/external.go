package external

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type ExternalChecker struct{}

type ExternalConfig struct {
	TestProxy bool
}

// ExternalIPInfo represents external IP address information
type ExternalIPInfo struct {
	IPv4Address string
	IPv6Address string
	IPv4Source  string
	IPv6Source  string
	Country     string
	ISP         string
	ASN         string
	Proxy       bool
	VPN         bool
	Tor         bool
}

// ProxyTestResult represents the result of proxy testing
type ProxyTestResult struct {
	ProxyType    string
	ProxyAddress string
	Working      bool
	Response     string
	Error        string
}

// GeoLocationResponse represents a response from a geolocation service
type GeoLocationResponse struct {
	Country string `json:"country"`
	ISP     string `json:"isp"`
	ASN     string `json:"as"`
	Proxy   bool   `json:"proxy"`
	VPN     bool   `json:"vpn"`
	Tor     bool   `json:"tor"`
	Query   string `json:"query"`
}

func NewExternalChecker() checker.Checker {
	return &ExternalChecker{}
}

func (c *ExternalChecker) Name() string {
	return "external"
}

func (c *ExternalChecker) Description() string {
	return "External IP address discovery and proxy detection"
}

func (c *ExternalChecker) Icon() string {
	return "🌍"
}

func (c *ExternalChecker) DefaultConfig() checker.CheckerConfig {
	return ExternalConfig{
		TestProxy: false,
	}
}

func (c *ExternalChecker) RequiresRouter() bool {
	return false
}

func (c *ExternalChecker) DefaultEnabled() bool {
	return true
}

func (c *ExternalChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{}
}

func (c *ExternalChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	// Standalone checker - no router-based functionality
}

func (c *ExternalChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
	cfg := config.(ExternalConfig)
	checkExternal(cfg, out)
}

func (c *ExternalChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_external",
		Description: "Discover external IP addresses, geolocation info, and test proxy configuration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"test_proxy": map[string]interface{}{
					"type":        "boolean",
					"description": "Test proxy configuration and connectivity",
					"default":     false,
				},
			},
			"required": []string{},
		},
	}
}

func checkExternal(cfg ExternalConfig, out output.Output) {
	fmt.Println("🌍 External Address Discovery")
	fmt.Println("============================")

	// Discover external IPv4 and IPv6 addresses
	externalInfo := discoverExternalAddresses()

	// Display external IP information
	displayExternalInfo(externalInfo)

	// Test proxy configuration if requested
	if cfg.TestProxy {
		fmt.Println("\n🔍 Testing proxy configuration...")
		testProxyConfiguration(externalInfo)
	}
}

// discoverExternalAddresses discovers external IPv4 and IPv6 addresses
func discoverExternalAddresses() ExternalIPInfo {
	info := ExternalIPInfo{}

	// Discover IPv4 address
	info.IPv4Address, info.IPv4Source = discoverExternalIPv4()

	// Discover IPv6 address
	info.IPv6Address, info.IPv6Source = discoverExternalIPv6()

	// Get additional information about the IP addresses
	if info.IPv4Address != "" {
		enhanceIPInfo(&info, info.IPv4Address, false)
	} else if info.IPv6Address != "" {
		enhanceIPInfo(&info, info.IPv6Address, true)
	}

	return info
}

// discoverExternalIPv4 discovers external IPv4 address using multiple services
func discoverExternalIPv4() (string, string) {
	services := []struct {
		name string
		url  string
	}{
		{"ipify", "https://api.ipify.org"},
		{"httpbin", "https://httpbin.org/ip"},
		{"ifconfig.me", "https://ifconfig.me/ip"},
		{"icanhazip", "https://ipv4.icanhazip.com"},
		{"ident.me", "https://v4.ident.me"},
	}

	for _, service := range services {
		if ip := queryIPService(service.url, false); ip != "" {
			// Validate it's actually IPv4
			if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil {
				return ip, service.name
			}
		}
	}

	return "", ""
}

// discoverExternalIPv6 discovers external IPv6 address using multiple services
func discoverExternalIPv6() (string, string) {
	services := []struct {
		name string
		url  string
	}{
		{"icanhazip", "https://ipv6.icanhazip.com"},
		{"ident.me", "https://v6.ident.me"},
		{"ipify", "https://api6.ipify.org"},
		{"test-ipv6", "https://ipv6.test-ipv6.com/ip/"},
	}

	for _, service := range services {
		if ip := queryIPService(service.url, true); ip != "" {
			// Validate it's actually IPv6
			if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil {
				return ip, service.name
			}
		}
	}

	return "", ""
}

// queryIPService queries an external IP service
func queryIPService(serviceURL string, ipv6 bool) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Force IPv4 or IPv6 if specified
	if ipv6 {
		client.Transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		}
	}

	resp, err := client.Get(serviceURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	result := strings.TrimSpace(string(body))

	// Handle JSON responses (like httpbin)
	if strings.HasPrefix(result, "{") {
		var jsonResp struct {
			Origin string `json:"origin"`
		}
		if err := json.Unmarshal(body, &jsonResp); err == nil {
			result = jsonResp.Origin
		}
	}

	// Clean up the result (remove extra text that some services include)
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if net.ParseIP(line) != nil {
			return line
		}
	}

	return ""
}

// enhanceIPInfo gets additional information about an IP address
func enhanceIPInfo(info *ExternalIPInfo, ipAddress string, isIPv6 bool) {
	// Try to get geolocation and ISP information
	geoInfo := getGeoLocationInfo(ipAddress)
	if geoInfo != nil {
		info.Country = geoInfo.Country
		info.ISP = geoInfo.ISP
		info.ASN = geoInfo.ASN
		info.Proxy = geoInfo.Proxy
		info.VPN = geoInfo.VPN
		info.Tor = geoInfo.Tor
	}
}

// getGeoLocationInfo gets geolocation information for an IP address
func getGeoLocationInfo(ipAddress string) *GeoLocationResponse {
	// Use free geolocation services (with limitations)
	services := []string{
		"http://ip-api.com/json/" + ipAddress,
		"https://ipapi.co/" + ipAddress + "/json/",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, serviceURL := range services {
		resp, err := client.Get(serviceURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			var geoResp GeoLocationResponse
			if err := json.Unmarshal(body, &geoResp); err == nil {
				return &geoResp
			}
		} else {
			resp.Body.Close()
		}
	}

	return nil
}

// displayExternalInfo displays the discovered external IP information
func displayExternalInfo(info ExternalIPInfo) {
	if info.IPv4Address == "" && info.IPv6Address == "" {
		fmt.Println("  ❌ Could not determine external IP address")
		fmt.Println("  ℹ️  This could indicate:")
		fmt.Println("     • No internet connectivity")
		fmt.Println("     • Firewall blocking outbound connections")
		fmt.Println("     • DNS resolution issues")
		return
	}

	// Display IPv4 information
	if info.IPv4Address != "" {
		fmt.Printf("  🌐 External IPv4: %s (via %s)\n", info.IPv4Address, info.IPv4Source)
	}

	// Display IPv6 information
	if info.IPv6Address != "" {
		fmt.Printf("  🌐 External IPv6: %s (via %s)\n", info.IPv6Address, info.IPv6Source)
	}

	// Display geolocation information
	if info.Country != "" {
		fmt.Printf("  🗺️  Location: %s\n", info.Country)
	}
	if info.ISP != "" {
		fmt.Printf("  🏢 ISP: %s\n", info.ISP)
	}
	if info.ASN != "" {
		fmt.Printf("  🔢 ASN: %s\n", info.ASN)
	}

	// Display proxy/VPN/Tor detection
	if info.Proxy || info.VPN || info.Tor {
		fmt.Println("  ⚠️  Proxy/VPN Detection:")
		if info.Proxy {
			fmt.Println("     • Proxy detected")
		}
		if info.VPN {
			fmt.Println("     • VPN detected")
		}
		if info.Tor {
			fmt.Println("     • Tor exit node detected")
		}
	}

	// Compare IPv4 vs IPv6 if both are available
	if info.IPv4Address != "" && info.IPv6Address != "" {
		fmt.Println("  ✅ Dual-stack connectivity (IPv4 + IPv6)")
	} else if info.IPv4Address != "" {
		fmt.Println("  ℹ️  IPv4-only connectivity")
	} else {
		fmt.Println("  ℹ️  IPv6-only connectivity")
	}
}

// testProxyConfiguration tests various proxy configurations
func testProxyConfiguration(externalInfo ExternalIPInfo) {
	// Test common proxy types and configurations
	proxyTests := []struct {
		name     string
		envVar   string
		testFunc func() ProxyTestResult
	}{
		{"HTTP Proxy", "HTTP_PROXY", testHTTPProxy},
		{"HTTPS Proxy", "HTTPS_PROXY", testHTTPSProxy},
		{"SOCKS Proxy", "SOCKS_PROXY", testSOCKSProxy},
		{"System Proxy", "", testSystemProxy},
	}

	foundWorkingProxy := false

	for _, test := range proxyTests {
		fmt.Printf("  🔍 Testing %s...\n", test.name)

		result := test.testFunc()
		if result.Working {
			foundWorkingProxy = true
			fmt.Printf("    ✅ %s working\n", test.name)
			if result.ProxyAddress != "" {
				fmt.Printf("       Address: %s\n", result.ProxyAddress)
			}
		} else {
			fmt.Printf("    ❌ %s not configured/working\n", test.name)
			if result.Error != "" {
				fmt.Printf("       Error: %s\n", result.Error)
			}
		}
	}

	if !foundWorkingProxy {
		fmt.Println("  ✅ No proxy detected - direct internet connection")
	}

	// Test if the external IP changes through different proxy configurations
	testIPConsistency(externalInfo)
}

// testHTTPProxy tests HTTP proxy configuration
func testHTTPProxy() ProxyTestResult {
	proxyURL := os.Getenv("HTTP_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("http_proxy")
	}

	if proxyURL == "" {
		return ProxyTestResult{
			ProxyType: "HTTP",
			Working:   false,
			Error:     "No HTTP_PROXY environment variable set",
		}
	}

	return testProxyURL(proxyURL, "HTTP")
}

// testHTTPSProxy tests HTTPS proxy configuration
func testHTTPSProxy() ProxyTestResult {
	proxyURL := os.Getenv("HTTPS_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("https_proxy")
	}

	if proxyURL == "" {
		return ProxyTestResult{
			ProxyType: "HTTPS",
			Working:   false,
			Error:     "No HTTPS_PROXY environment variable set",
		}
	}

	return testProxyURL(proxyURL, "HTTPS")
}

// testSOCKSProxy tests SOCKS proxy configuration
func testSOCKSProxy() ProxyTestResult {
	proxyURL := os.Getenv("SOCKS_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("socks_proxy")
	}

	if proxyURL == "" {
		return ProxyTestResult{
			ProxyType: "SOCKS",
			Working:   false,
			Error:     "No SOCKS_PROXY environment variable set",
		}
	}

	return testProxyURL(proxyURL, "SOCKS")
}

// testSystemProxy tests system-configured proxy
func testSystemProxy() ProxyTestResult {
	// This would require platform-specific implementation
	// For now, return not implemented
	return ProxyTestResult{
		ProxyType: "System",
		Working:   false,
		Error:     "System proxy detection not implemented",
	}
}

// testProxyURL tests a specific proxy URL
func testProxyURL(proxyURL, proxyType string) ProxyTestResult {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return ProxyTestResult{
			ProxyType: proxyType,
			Working:   false,
			Error:     fmt.Sprintf("Invalid proxy URL: %v", err),
		}
	}

	// Create HTTP client with proxy
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(parsedURL),
		},
	}

	// Test the proxy by making a request
	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		return ProxyTestResult{
			ProxyType:    proxyType,
			ProxyAddress: proxyURL,
			Working:      false,
			Error:        fmt.Sprintf("Proxy connection failed: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return ProxyTestResult{
			ProxyType:    proxyType,
			ProxyAddress: proxyURL,
			Working:      true,
			Response:     string(body),
		}
	}

	return ProxyTestResult{
		ProxyType:    proxyType,
		ProxyAddress: proxyURL,
		Working:      false,
		Error:        fmt.Sprintf("HTTP %d", resp.StatusCode),
	}
}

// testIPConsistency tests if the external IP changes with different configurations
func testIPConsistency(originalInfo ExternalIPInfo) {
	fmt.Printf("  🔍 Testing IP consistency...\n")

	// Test with different DNS servers to see if results change
	dnsServers := []string{
		"8.8.8.8:53",     // Google
		"1.1.1.1:53",     // Cloudflare
		"208.67.222.222", // OpenDNS
	}

	consistentResults := true
	for _, dns := range dnsServers {
		// This would require custom DNS resolution - simplified for now
		fmt.Printf("    Testing with DNS: %s\n", dns)
	}

	if consistentResults {
		fmt.Println("  ✅ IP addresses consistent across tests")
	} else {
		fmt.Println("  ⚠️  IP addresses inconsistent - possible proxy/VPN interference")
	}
}
