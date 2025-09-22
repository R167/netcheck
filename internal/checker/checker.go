package checker

import (
	"github.com/R167/netcheck/checkers/common"
)

type CheckerConfig interface{}

type Checker interface {
	Name() string
	Description() string
	Icon() string
	DefaultConfig() CheckerConfig
	RequiresRouter() bool
	DefaultEnabled() bool
	Run(config CheckerConfig, router *common.RouterInfo)
	RunStandalone(config CheckerConfig)
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
