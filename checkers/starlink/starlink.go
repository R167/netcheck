package starlink

import (
	"fmt"

	starlinklib "github.com/R167/netcheck/starlink"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
)

type StarlinkChecker struct{}

type StarlinkConfig struct{}

func NewStarlinkChecker() checker.Checker {
	return &StarlinkChecker{}
}

func (c *StarlinkChecker) Name() string {
	return "starlink"
}

func (c *StarlinkChecker) Description() string {
	return "Starlink Dishy detection and security assessment"
}

func (c *StarlinkChecker) Icon() string {
	return "🛰️"
}

func (c *StarlinkChecker) DefaultConfig() checker.CheckerConfig {
	return StarlinkConfig{}
}

func (c *StarlinkChecker) RequiresRouter() bool {
	return true
}

func (c *StarlinkChecker) DefaultEnabled() bool {
	return false
}

func (c *StarlinkChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyNetwork, checker.DependencyRouterInfo}
}

func (c *StarlinkChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	checkStarlink(router)
}

func (c *StarlinkChecker) RunStandalone(config checker.CheckerConfig) {
	// Router-based checker - no standalone functionality
}

func (c *StarlinkChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_starlink",
		Description: "Detect and analyze Starlink Dishy satellite terminals on the network",
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

func checkStarlink(router *common.RouterInfo) {
	fmt.Println("🛰️  Checking for Starlink Dishy...")
	starlinkInfo := starlinklib.CheckStarlink()
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
				router.Issues = append(router.Issues, common.SecurityIssue{
					Severity:    issue.Severity,
					Description: issue.Title,
					Details:     issue.Description + " Impact: " + issue.Impact,
				})
			}
		} else {
			fmt.Println("  ✅ No security issues detected")
		}
	} else {
		fmt.Println("  ℹ️  No Starlink Dishy detected")
	}
}
