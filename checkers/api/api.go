package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
)

type APIChecker struct{}

type APIConfig struct{}

// APIEndpoint represents a router API endpoint with security implications
type APIEndpoint struct {
	Path        string
	Description string
	Severity    string
}

// Common router API endpoints
var routerAPIEndpoints = []APIEndpoint{
	{"/api/", "Generic API endpoint", common.SeverityMedium},
	{"/cgi-bin/", "CGI scripts", common.SeverityHigh},
	{"/status.xml", "Status XML", common.SeverityLow},
	{"/info.html", "Device info", common.SeverityLow},
	{"/system.xml", "System XML", common.SeverityMedium},
	{"/wan.xml", "WAN configuration", common.SeverityMedium},
	{"/wireless.xml", "Wireless config", common.SeverityMedium},
	{"/tr069", "TR-069 management", common.SeverityHigh},
	{"/remote/", "Remote management", common.SeverityHigh},
	{"/goform/", "Form handlers", common.SeverityMedium},
	{"/boaform/", "BOA form handlers", common.SeverityMedium},
}

// Common WPS-related paths
var wpsPaths = []string{
	"/wps.html",
	"/wireless_wps.html",
	"/wps_setup.html",
	"/advanced_wireless_wps.html",
}

func NewAPIChecker() checker.Checker {
	return &APIChecker{}
}

func (c *APIChecker) Name() string {
	return "api"
}

func (c *APIChecker) Description() string {
	return "Router API endpoints and WPS security assessment"
}

func (c *APIChecker) Icon() string {
	return "🔍"
}

func (c *APIChecker) DefaultConfig() checker.CheckerConfig {
	return APIConfig{}
}

func (c *APIChecker) RequiresRouter() bool {
	return true
}

func (c *APIChecker) DefaultEnabled() bool {
	return true
}

func (c *APIChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	checkRouterAPIs(router)
}

func (c *APIChecker) RunStandalone(config checker.CheckerConfig) {
	// Router-based checker - no standalone functionality
}

func (c *APIChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_api",
		Description: "Scan for exposed router API endpoints and WPS configuration vulnerabilities",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func checkRouterAPIs(router *common.RouterInfo) {
	fmt.Println("\n🔍 Checking for exposed APIs and services...")
	client := &http.Client{Timeout: common.HTTPTimeout}

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
			if endpoint.Severity == common.SeverityHigh {
				router.Issues = append(router.Issues, common.SecurityIssue{
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

func checkWPS(router *common.RouterInfo) {
	fmt.Println("\n🔍 Checking WPS configuration...")
	client := &http.Client{Timeout: common.HTTPTimeout}

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
				router.Issues = append(router.Issues, common.SecurityIssue{
					Severity:    common.SeverityMedium,
					Description: "WPS (WiFi Protected Setup) may be enabled",
					Details:     "WPS has known security vulnerabilities and should be disabled if not needed.",
				})
				return
			}
		}
	}

	fmt.Println("  ℹ️  WPS configuration not accessible")
}
