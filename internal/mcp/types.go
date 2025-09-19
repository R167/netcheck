package mcp

type CheckToolInput struct {
	GatewayIP         string `json:"gateway_ip,omitempty"`
	Ports             []int  `json:"ports,omitempty"`
	CheckDefaultCreds bool   `json:"check_default_creds,omitempty"`
	EnumerateMappings bool   `json:"enumerate_mappings,omitempty"`
	Comprehensive     bool   `json:"comprehensive,omitempty"`
}

type CheckToolOutput struct {
	Issues  []Issue `json:"issues"`
	Summary string  `json:"summary"`
	Report  string  `json:"report"`
}

type Issue struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Details     string `json:"details"`
}