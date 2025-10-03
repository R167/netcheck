package starlink

import (
	starlinklib "github.com/R167/netcheck/starlink"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
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

func (c *StarlinkChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	checkStarlink(router, out)
}

func (c *StarlinkChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
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

func checkStarlink(router *common.RouterInfo, out output.Output) {
	out.Section("🛰️", "Checking for Starlink Dishy...")
	starlinkInfo := starlinklib.CheckStarlink(out)
	router.Starlink = starlinkInfo

	if starlinkInfo.Accessible {
		out.Info("📡 Starlink Dishy detected and accessible")
		if starlinkInfo.DeviceInfo != nil {
			out.Info("🔧 Hardware: %s", starlinkInfo.DeviceInfo.HardwareVersion)
			out.Info("💾 Software: %s", starlinkInfo.DeviceInfo.SoftwareVersion)
		}

		if len(starlinkInfo.SecurityIssues) > 0 {
			out.Warning("Found %d security issue(s)", len(starlinkInfo.SecurityIssues))
			// Add Starlink security issues to router issues with proper format conversion
			for _, issue := range starlinkInfo.SecurityIssues {
				router.Issues = append(router.Issues, common.SecurityIssue{
					Severity:    issue.Severity,
					Description: issue.Title,
					Details:     issue.Description + " Impact: " + issue.Impact,
				})
			}
		} else {
			out.Success("No security issues detected")
		}
	} else {
		out.Info("ℹ️  No Starlink Dishy detected")
	}
}
