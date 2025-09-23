package checker

import (
	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/output"
)

type CheckerConfig interface{}

// Dependency represents a resource or prerequisite that a checker requires to run.
// Checkers declare their dependencies via the Dependencies() method, allowing the
// runner to optimize resource discovery and ensure prerequisites are met.
type Dependency string

const (
	// DependencyGateway indicates the checker requires the gateway IP address to be discovered.
	// The runner will perform gateway discovery and make the IP available before executing the checker.
	// Example: Checkers that scan the router directly (web, ports, api)
	DependencyGateway Dependency = "gateway"

	// DependencyRouterInfo indicates the checker requires a RouterInfo struct to store results.
	// This is needed by all checkers that mutate router state or add security issues.
	// Example: All router-based checkers that populate findings
	DependencyRouterInfo Dependency = "router-info"

	// DependencyNetwork indicates the checker requires active network connectivity.
	// The runner may perform network availability checks before executing.
	// Example: Checkers that perform network multicast/broadcast (upnp, ssdp, mdns)
	DependencyNetwork Dependency = "network"
)

// Checker defines the interface that all security checkers must implement.
// Checkers are modular security assessment components that test specific
// aspects of network gateway configuration (e.g., UPnP, default credentials).
type Checker interface {
	// Name returns the unique identifier for this checker (e.g., "web", "upnp").
	// This is used for flag generation and logging.
	Name() string

	// Description returns a human-readable description of what this checker does.
	Description() string

	// Icon returns an emoji or symbol representing this checker in output.
	Icon() string

	// DefaultConfig returns the default configuration for this checker.
	DefaultConfig() CheckerConfig

	// RequiresRouter returns true if this checker needs router access to run.
	// False indicates a standalone checker (e.g., routes, device info).
	RequiresRouter() bool

	// DefaultEnabled returns true if this checker should run by default.
	// False means it requires an explicit --flag to run.
	DefaultEnabled() bool

	// Dependencies returns the list of resources this checker needs to run.
	// The runner uses this to ensure prerequisites are met before execution.
	Dependencies() []Dependency

	// Run executes the checker against a router with the given configuration.
	// The checker should mutate the router parameter to add findings and use
	// the output interface for all printing.
	Run(config CheckerConfig, router *common.RouterInfo, out output.Output)

	// RunStandalone executes the checker without router context.
	// Only used by standalone checkers (RequiresRouter() == false).
	RunStandalone(config CheckerConfig, out output.Output)

	// MCPToolDefinition returns the MCP tool schema for this checker.
	// Used when running in MCP server mode for protocol integration.
	MCPToolDefinition() *MCPTool
}

type MCPTool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
}

type CheckFlag struct {
	Name           string
	Description    string
	Icon           string
	Checker        Checker
	RequiresRouter bool
	DefaultEnabled bool
}

// BaseChecker provides default implementations for common checker methods.
// Checkers can embed this to get sensible defaults (e.g., no dependencies for standalone checkers).
// Note: Currently not used by checkers as they implement Dependencies() directly.
// Kept for future use and backward compatibility.
type BaseChecker struct{}

// Dependencies returns an empty dependency list by default.
// Checkers with specific requirements override this method.
func (b *BaseChecker) Dependencies() []Dependency {
	return []Dependency{}
}
