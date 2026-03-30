package mcp

import "github.com/R167/netcheck/checkers/common"

// ToolInput is the universal input for all MCP tools.
// Each tool uses the subset of fields relevant to it.
type ToolInput struct {
	GatewayIP string `json:"gateway_ip,omitempty"`

	// Port scanning
	Ports []int `json:"ports,omitempty"`

	// Web checker
	CheckDefaultCreds bool `json:"check_default_creds,omitempty"`

	// UPnP
	EnumerateMappings   bool `json:"enumerate_mappings,omitempty"`
	CheckIPv6Firewall   bool `json:"check_ipv6_firewall,omitempty"`
	EnumerateServices   bool `json:"enumerate_services,omitempty"`
	CheckSecurityIssues bool `json:"check_security_issues,omitempty"`

	// mDNS
	Detailed bool `json:"detailed,omitempty"`

	// SSDP
	IPv4Enabled   bool     `json:"ipv4_enabled,omitempty"`
	IPv6Enabled   bool     `json:"ipv6_enabled,omitempty"`
	SearchTargets []string `json:"search_targets,omitempty"`

	// Device/IPv6
	ShowVirtual bool `json:"show_virtual,omitempty"`

	// External
	TestProxy bool `json:"test_proxy,omitempty"`

	// Checkers to run (for full_scan)
	Checkers []string `json:"checkers,omitempty"`
}

// ToolOutput is the structured response from all MCP tools.
type ToolOutput struct {
	// Summary is a one-line description of results.
	Summary string `json:"summary"`

	// Gateway info (populated by discover_network and full_scan).
	Gateway *GatewayInfo `json:"gateway,omitempty"`

	// Router state after checks (populated by router-based checks).
	Router *RouterState `json:"router,omitempty"`

	// Issues found during the check.
	Issues []Issue `json:"issues,omitempty"`

	// Services discovered (UPnP, SSDP, mDNS).
	Services []Service `json:"services,omitempty"`

	// Port mappings found (UPnP).
	PortMappings []common.PortMapping `json:"port_mappings,omitempty"`

	// Log is the human-readable output from the checker.
	Log string `json:"log,omitempty"`
}

// GatewayInfo describes the discovered network gateway.
type GatewayInfo struct {
	IP         string   `json:"ip"`
	Interfaces []NetIf  `json:"interfaces,omitempty"`
	ExternalIP string   `json:"external_ip,omitempty"`
	Routes     []string `json:"routes,omitempty"`
}

// NetIf describes a local network interface.
type NetIf struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac,omitempty"`
	Flags string   `json:"flags,omitempty"`
}

// RouterState is a summary of router findings.
type RouterState struct {
	IP            string `json:"ip"`
	Vendor        string `json:"vendor,omitempty"`
	Model         string `json:"model,omitempty"`
	WebInterface  bool   `json:"web_interface"`
	DefaultCreds  bool   `json:"default_creds"`
	UPnPEnabled   bool   `json:"upnp_enabled"`
	NATpmpEnabled bool   `json:"natpmp_enabled"`
	IPv6Enabled   bool   `json:"ipv6_enabled"`
	MDNSEnabled   bool   `json:"mdns_enabled"`
	SSDPEnabled   bool   `json:"ssdp_enabled"`
	OpenPorts     []int  `json:"open_ports,omitempty"`
}

// Issue represents a security finding.
type Issue struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Details     string `json:"details"`
}

// Service represents a discovered network service.
type Service struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Details  string `json:"details,omitempty"`
}

// RouterStateFromInfo converts a common.RouterInfo to the MCP RouterState.
func RouterStateFromInfo(r *common.RouterInfo) *RouterState {
	return &RouterState{
		IP:            r.IP,
		Vendor:        r.Vendor,
		Model:         r.Model,
		WebInterface:  r.WebInterface,
		DefaultCreds:  r.DefaultCreds,
		UPnPEnabled:   r.UPnPEnabled,
		NATpmpEnabled: r.NATpmpEnabled,
		IPv6Enabled:   r.IPv6Enabled,
		MDNSEnabled:   r.MDNSEnabled,
		SSDPEnabled:   r.SSDPEnabled,
		OpenPorts:     r.OpenPorts,
	}
}

// IssuesFromInfo converts common.SecurityIssues to MCP Issues.
func IssuesFromInfo(issues []common.SecurityIssue) []Issue {
	out := make([]Issue, len(issues))
	for i, iss := range issues {
		out[i] = Issue{
			Severity:    iss.Severity,
			Description: iss.Description,
			Details:     iss.Details,
		}
	}
	return out
}

// ServicesFromMDNS converts mDNS services to generic Service entries.
func ServicesFromMDNS(services []common.MDNSService) []Service {
	out := make([]Service, len(services))
	for i, s := range services {
		out[i] = Service{
			Type: s.Type,
			Name: s.Name,
			IP:   s.IP,
			Port: s.Port,
		}
	}
	return out
}

// ServicesFromSSDP converts SSDP services to generic Service entries.
func ServicesFromSSDP(services []common.SSDPService) []Service {
	out := make([]Service, len(services))
	for i, s := range services {
		out[i] = Service{
			Type:     s.DeviceType,
			Name:     s.FriendlyName,
			Protocol: "ssdp",
			Details:  s.Location,
		}
	}
	return out
}

// ServicesFromUPnP converts UPnP services to generic Service entries.
func ServicesFromUPnP(services []common.UPnPService) []Service {
	out := make([]Service, len(services))
	for i, s := range services {
		out[i] = Service{
			Type:     s.ServiceType,
			Name:     s.ServiceID,
			Protocol: "upnp",
			Details:  s.ControlURL,
		}
	}
	return out
}
