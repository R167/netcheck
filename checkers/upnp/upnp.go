package upnp

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type UPnPChecker struct{}

type UPnPConfig struct {
	EnumerateMappings   bool
	CheckIPv6Firewall   bool
	EnumerateServices   bool
	CheckSecurityIssues bool
}

func NewUPnPChecker() checker.Checker {
	return &UPnPChecker{}
}

func (c *UPnPChecker) Name() string {
	return "upnp"
}

func (c *UPnPChecker) Description() string {
	return "UPnP services and port mappings"
}

func (c *UPnPChecker) Icon() string {
	return "🔍"
}

func (c *UPnPChecker) DefaultConfig() checker.CheckerConfig {
	return UPnPConfig{
		EnumerateMappings:   true,
		CheckIPv6Firewall:   true,
		EnumerateServices:   true,
		CheckSecurityIssues: true,
	}
}

func (c *UPnPChecker) RequiresRouter() bool {
	return true
}

func (c *UPnPChecker) DefaultEnabled() bool {
	return true
}

func (c *UPnPChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyGateway, checker.DependencyRouterInfo, checker.DependencyNetwork}
}

func (c *UPnPChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	cfg := config.(UPnPConfig)
	checkUPnP(router, cfg, out)
}

func (c *UPnPChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
}

func (c *UPnPChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_upnp",
		Description: "Comprehensive UPnP IGD v2.0 security assessment including IPv6 firewall control and service enumeration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
				"enumerate_mappings": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to enumerate active IPv4 port mappings",
					"default":     true,
				},
				"check_ipv6_firewall": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to check IPv6 firewall control and pinholes",
					"default":     true,
				},
				"enumerate_services": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to enumerate all UPnP services including vendor extensions",
					"default":     true,
				},
				"check_security_issues": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to test for dangerous UPnP security vulnerabilities",
					"default":     true,
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func checkUPnP(router *common.RouterInfo, cfg UPnPConfig, out output.Output) {
	out.Section("🔍", "Checking UPnP services...")

	upnpInfo := checkSSDPMulticast()
	if upnpInfo != nil {
		router.UPnPEnabled = true
		out.Info("📡 UPnP SSDP discovered")
		out.Info("🔗 Location: %s", upnpInfo.Location)
		out.Info("🖥️  Server: %s", upnpInfo.Server)

		if desc := getUPnPDescriptionFromURL(upnpInfo.Location); desc != nil {
			out.Info("📄 Device: %s (%s)", desc.FriendlyName, desc.Manufacturer)
			if desc.ModelName != "" {
				router.Model = desc.ModelName
			}
			if desc.SerialNumber != "" {
				router.SerialNumber = desc.SerialNumber
				out.Info("🔢 Serial: %s", desc.SerialNumber)
			}
			if desc.PresentationURL != "" {
				out.Info("🌐 Admin URL: %s", desc.PresentationURL)
			}

			if cfg.EnumerateServices {
				enumerateUPnPServices(router, upnpInfo.Location, out)
			}

			if cfg.EnumerateMappings {
				checkUPnPPortMappings(router, upnpInfo.Location, out)
			}

			if cfg.CheckIPv6Firewall {
				checkIPv6FirewallControl(router, upnpInfo.Location, out)
			}

			if cfg.CheckSecurityIssues {
				checkUPnPSecurityIssues(router, upnpInfo.Location, out)
			}
		}

		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    "MEDIUM",
			Description: "UPnP service is enabled",
			Details:     "UPnP can expose internal services and allow port forwarding. Ensure it's properly configured.",
		})
	} else {
		upnpPorts := []int{1900, 5000, 49152, 49153, 49154}
		for _, port := range upnpPorts {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(router.IP, strconv.Itoa(port)), common.PortTimeout)
			if err != nil {
				continue
			}
			conn.Close()

			router.UPnPEnabled = true
			out.Success("UPnP service on port %d", port)

			if desc := getUPnPDescription(router.IP, port); desc != nil {
				out.Info("📄 Device: %s (%s)", desc.FriendlyName, desc.Manufacturer)
				if desc.ModelName != "" {
					router.Model = desc.ModelName
				}
			}
		}
	}

	if !router.UPnPEnabled {
		out.Success("No UPnP services detected")
	}
}

func checkSSDPMulticast() *common.SSDPResponse {
	localAddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	multicastAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil
	}

	ssdpRequest := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n" +
		"MX: 3\r\n\r\n"

	_, err = conn.WriteTo([]byte(ssdpRequest), multicastAddr)
	if err != nil {
		return nil
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 2048)

	for i := 0; i < 3; i++ {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			continue
		}

		response := string(buffer[:n])
		if ssdp := parseSSDPResponse(response); ssdp != nil {
			return ssdp
		}
	}

	return nil
}

func parseSSDPResponse(response string) *common.SSDPResponse {
	lines := strings.Split(response, "\r\n")
	ssdp := &common.SSDPResponse{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			ssdp.Location = strings.TrimSpace(line[9:])
		} else if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			ssdp.Server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(strings.ToUpper(line), "USN:") {
			ssdp.USN = strings.TrimSpace(line[4:])
		}
	}

	if ssdp.Location != "" {
		return ssdp
	}
	return nil
}

func getUPnPDescription(ip string, port int) *common.UPnPDevice {
	client := &http.Client{Timeout: 3 * time.Second}

	paths := []string{
		"/rootDesc.xml",
		"/description.xml",
		"/device.xml",
		"/upnp/description.xml",
	}

	for _, path := range paths {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var device common.UPnPDevice
			if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
				return &device
			}
		}
	}
	return nil
}

func getUPnPDescriptionFromURL(url string) *common.UPnPDevice {
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var device common.UPnPDevice
		if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
			return &device
		}
	}
	return nil
}

func checkUPnPPortMappings(router *common.RouterInfo, baseURL string, out output.Output) {
	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	mappings := getPortMappings(soapBaseURL)
	if len(mappings) > 0 {
		router.PortMappings = mappings
		out.Info("🔓 Found %d port mapping(s)", len(mappings))

		for _, mapping := range mappings {
			out.Info("  %s:%d → %s:%d (%s)",
				"*", mapping.ExternalPort,
				mapping.InternalIP, mapping.InternalPort,
				mapping.Protocol)
		}

		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    "HIGH",
			Description: "Active UPnP port mappings detected",
			Details:     fmt.Sprintf("Found %d active port forwarding rules that may expose internal services", len(mappings)),
		})
	}
}

func getPortMappings(baseURL string) []common.PortMapping {
	client := &http.Client{Timeout: 5 * time.Second}
	var mappings []common.PortMapping

	for i := 0; i < 50; i++ {
		soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewPortMappingIndex>%d</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>`, i)

		req, err := http.NewRequest("POST", baseURL+"/ctl/IPConn", strings.NewReader(soapBody))
		if err != nil {
			break
		}

		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:2#GetGenericPortMappingEntry"`)

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			break
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			break
		}

		content := string(body)
		if strings.Contains(content, "NewExternalPort") {
			mapping := parsePortMapping(content)
			if mapping.ExternalPort > 0 {
				mappings = append(mappings, mapping)
			}
		} else {
			break
		}
	}

	return mappings
}

func parsePortMapping(soapResponse string) common.PortMapping {
	mapping := common.PortMapping{}

	if match := regexp.MustCompile(`<NewExternalPort>(\d+)</NewExternalPort>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			mapping.ExternalPort = port
		}
	}
	if match := regexp.MustCompile(`<NewInternalPort>(\d+)</NewInternalPort>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			mapping.InternalPort = port
		}
	}
	if match := regexp.MustCompile(`<NewInternalClient>([^<]+)</NewInternalClient>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		mapping.InternalIP = match[1]
	}
	if match := regexp.MustCompile(`<NewProtocol>([^<]+)</NewProtocol>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		mapping.Protocol = match[1]
	}
	if match := regexp.MustCompile(`<NewPortMappingDescription>([^<]+)</NewPortMappingDescription>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		mapping.Description = match[1]
	}

	return mapping
}

func enumerateUPnPServices(router *common.RouterInfo, baseURL string, out output.Output) {
	out.Section("🔎", "Enumerating UPnP services...")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)

	serviceTypeRegex := regexp.MustCompile(`<serviceType>([^<]+)</serviceType>`)
	serviceIDRegex := regexp.MustCompile(`<serviceId>([^<]+)</serviceId>`)
	controlURLRegex := regexp.MustCompile(`<controlURL>([^<]+)</controlURL>`)

	serviceTypes := serviceTypeRegex.FindAllStringSubmatch(content, -1)
	serviceIDs := serviceIDRegex.FindAllStringSubmatch(content, -1)
	controlURLs := controlURLRegex.FindAllStringSubmatch(content, -1)

	standardServices := map[string]bool{
		"WANIPConnection":          true,
		"WANPPPConnection":         true,
		"WANCommonInterfaceConfig": true,
		"Layer3Forwarding":         true,
		"WANIPv6FirewallControl":   true,
		"DeviceProtection":         true,
	}

	for i := 0; i < len(serviceTypes) && i < len(serviceIDs) && i < len(controlURLs); i++ {
		if len(serviceTypes[i]) < 2 || len(serviceIDs[i]) < 2 || len(controlURLs[i]) < 2 {
			continue
		}

		serviceType := serviceTypes[i][1]
		serviceID := serviceIDs[i][1]
		controlURL := controlURLs[i][1]

		isStandard := false
		for std := range standardServices {
			if strings.Contains(serviceType, std) {
				isStandard = true
				break
			}
		}

		service := common.UPnPService{
			ServiceType: serviceType,
			ServiceID:   serviceID,
			ControlURL:  controlURL,
			IsStandard:  isStandard,
		}

		router.UPnPServices = append(router.UPnPServices, service)

		if !isStandard {
			out.Warning("Non-standard service: %s", serviceType)
		} else {
			out.Info("✓ %s", serviceType)
		}
	}

	if len(router.UPnPServices) > 0 {
		nonStandardCount := 0
		for _, svc := range router.UPnPServices {
			if !svc.IsStandard {
				nonStandardCount++
			}
		}

		if nonStandardCount > 0 {
			router.Issues = append(router.Issues, common.SecurityIssue{
				Severity:    "LOW",
				Description: fmt.Sprintf("Non-standard UPnP services detected (%d)", nonStandardCount),
				Details:     "Vendor-specific or non-standard UPnP services may have undocumented security implications.",
			})
		}
	}
}

func checkIPv6FirewallControl(router *common.RouterInfo, baseURL string, out output.Output) {
	out.Section("🛡️", "Checking IPv6 Firewall Control...")

	// Find the IPv6 firewall control service
	var ipv6Service *common.UPnPService
	for _, svc := range router.UPnPServices {
		if strings.Contains(svc.ServiceType, "WANIPv6FirewallControl") {
			ipv6Service = &svc
			break
		}
	}

	if ipv6Service == nil {
		out.Info("ℹ️  IPv6 Firewall Control not available")
		return
	}

	out.Info("📡 IPv6 Firewall Control service detected")

	// Extract base URL for SOAP requests
	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	// Get firewall status using the correct control URL
	status := getIPv6FirewallStatus(soapBaseURL, ipv6Service.ControlURL)
	if status != nil {
		out.Info("🔥 Firewall Enabled: %t", status.FirewallEnabled)
		out.Info("🔓 Inbound Pinholes Allowed: %t", status.InboundPinholeAllowed)

		// Note: IPv6 firewall control service doesn't provide pinhole enumeration
		// Unlike IPv4 port mappings, there's no standard way to list all pinholes
		out.Info("ℹ️  IPv6 pinhole enumeration not supported by UPnP standard")

		// If pinholes are allowed but firewall is enabled, it's a potential security concern
		if status.InboundPinholeAllowed {
			router.Issues = append(router.Issues, common.SecurityIssue{
				Severity:    "MEDIUM",
				Description: "IPv6 inbound pinholes are allowed",
				Details:     "The router allows creation of IPv6 firewall pinholes, which could expose internal services. Monitor for unauthorized pinhole creation.",
			})
		}

		if !status.FirewallEnabled {
			router.Issues = append(router.Issues, common.SecurityIssue{
				Severity:    "HIGH",
				Description: "IPv6 firewall is disabled",
				Details:     "IPv6 firewall protection is disabled, potentially exposing internal services to the internet.",
			})
		} else {
			out.Success("IPv6 firewall is properly enabled")
		}
	} else {
		out.Warning("Could not retrieve IPv6 firewall status")
	}
}

type IPv6FirewallStatus struct {
	FirewallEnabled       bool
	InboundPinholeAllowed bool
}

func getIPv6FirewallStatus(baseURL, controlURL string) *IPv6FirewallStatus {
	client := &http.Client{Timeout: 5 * time.Second}

	soapBody := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetFirewallStatus xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1">
</u:GetFirewallStatus>
</s:Body>
</s:Envelope>`

	req, err := http.NewRequest("POST", baseURL+controlURL, strings.NewReader(soapBody))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1#GetFirewallStatus"`)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := string(body)
	status := &IPv6FirewallStatus{}

	// Parse FirewallEnabled
	if match := regexp.MustCompile(`<FirewallEnabled>(\d+)</FirewallEnabled>`).FindStringSubmatch(content); len(match) > 1 {
		status.FirewallEnabled = match[1] == "1"
	}

	// Parse InboundPinholeAllowed
	if match := regexp.MustCompile(`<InboundPinholeAllowed>(\d+)</InboundPinholeAllowed>`).FindStringSubmatch(content); len(match) > 1 {
		status.InboundPinholeAllowed = match[1] == "1"
	}

	return status
}

// Note: parseIPv6Pinhole function removed as IPv6 firewall control
// does not provide a standard method to enumerate existing pinholes.
// Individual pinholes can only be checked if their UniqueID is known.

func checkUPnPSecurityIssues(router *common.RouterInfo, baseURL string, out output.Output) {
	out.Section("🔒", "Checking UPnP security issues...")

	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	testAddPortMapping := func(targetIP string) bool {
		soapBody := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>65534</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>65534</NewInternalPort>
<NewInternalClient>` + targetIP + `</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Security Test</NewPortMappingDescription>
<NewLeaseDuration>60</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`

		client := &http.Client{Timeout: 3 * time.Second}
		req, err := http.NewRequest("POST", soapBaseURL+"/ctl/IPConn", strings.NewReader(soapBody))
		if err != nil {
			return false
		}

		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:2#AddPortMapping"`)

		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		return resp.StatusCode == 200
	}

	if testAddPortMapping("192.168.1.99") {
		out.Warning("UPnP allows port mapping to arbitrary internal IPs")

		deletePortMapping := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>65534</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>`

		client := &http.Client{Timeout: 3 * time.Second}
		req, _ := http.NewRequest("POST", soapBaseURL+"/ctl/IPConn", strings.NewReader(deletePortMapping))
		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:2#DeletePortMapping"`)
		client.Do(req)

		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    "CRITICAL",
			Description: "UPnP allows port mapping to arbitrary devices",
			Details:     "Any device on the network can create port forwards to ANY internal IP, not just itself. This allows lateral movement attacks.",
		})
	} else {
		out.Success("UPnP properly restricts port mappings to requesting device")
	}
}
