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

func (c *UPnPChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	cfg := config.(UPnPConfig)
	checkUPnP(router, cfg)
}

func (c *UPnPChecker) RunStandalone(config checker.CheckerConfig) {
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

func checkUPnP(router *common.RouterInfo, cfg UPnPConfig) {
	fmt.Println("\n🔍 Checking UPnP services...")

	upnpInfo := checkSSDPMulticast()
	if upnpInfo != nil {
		router.UPnPEnabled = true
		fmt.Println("  📡 UPnP SSDP discovered")
		fmt.Printf("  🔗 Location: %s\n", upnpInfo.Location)
		fmt.Printf("  🖥️  Server: %s\n", upnpInfo.Server)

		if desc := getUPnPDescriptionFromURL(upnpInfo.Location); desc != nil {
			fmt.Printf("  📄 Device: %s (%s)\n", desc.FriendlyName, desc.Manufacturer)
			if desc.ModelName != "" {
				router.Model = desc.ModelName
			}
			if desc.SerialNumber != "" {
				router.SerialNumber = desc.SerialNumber
				fmt.Printf("  🔢 Serial: %s\n", desc.SerialNumber)
			}
			if desc.PresentationURL != "" {
				fmt.Printf("  🌐 Admin URL: %s\n", desc.PresentationURL)
			}

			if cfg.EnumerateServices {
				enumerateUPnPServices(router, upnpInfo.Location)
			}

			if cfg.EnumerateMappings {
				checkUPnPPortMappings(router, upnpInfo.Location)
			}

			if cfg.CheckIPv6Firewall {
				checkIPv6FirewallControl(router, upnpInfo.Location)
			}

			if cfg.CheckSecurityIssues {
				checkUPnPSecurityIssues(router, upnpInfo.Location)
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
			fmt.Printf("  ✅ UPnP service on port %d\n", port)

			if desc := getUPnPDescription(router.IP, port); desc != nil {
				fmt.Printf("  📄 Device: %s (%s)\n", desc.FriendlyName, desc.Manufacturer)
				if desc.ModelName != "" {
					router.Model = desc.ModelName
				}
			}
		}
	}

	if !router.UPnPEnabled {
		fmt.Println("  ✅ No UPnP services detected")
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

func checkUPnPPortMappings(router *common.RouterInfo, baseURL string) {
	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	mappings := getPortMappings(soapBaseURL)
	if len(mappings) > 0 {
		router.PortMappings = mappings
		fmt.Printf("  🔓 Found %d port mapping(s)\n", len(mappings))

		for _, mapping := range mappings {
			fmt.Printf("    %s:%d → %s:%d (%s)\n",
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

func enumerateUPnPServices(router *common.RouterInfo, baseURL string) {
	fmt.Println("\n  🔎 Enumerating UPnP services...")

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
			fmt.Printf("    ⚠️  Non-standard service: %s\n", serviceType)
		} else {
			fmt.Printf("    ✓ %s\n", serviceType)
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

func checkIPv6FirewallControl(router *common.RouterInfo, baseURL string) {
	fmt.Println("\n  🛡️  Checking IPv6 Firewall Control...")

	hasIPv6Firewall := false
	for _, svc := range router.UPnPServices {
		if strings.Contains(svc.ServiceType, "WANIPv6FirewallControl") {
			hasIPv6Firewall = true
			break
		}
	}

	if !hasIPv6Firewall {
		fmt.Println("    ℹ️  IPv6 Firewall Control not available")
		return
	}

	fmt.Println("    📡 IPv6 Firewall Control service detected")

	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	pinholes := getIPv6Pinholes(soapBaseURL)
	if len(pinholes) > 0 {
		router.IPv6Pinholes = pinholes
		fmt.Printf("    🔓 Found %d IPv6 pinhole(s)\n", len(pinholes))

		for _, pinhole := range pinholes {
			fmt.Printf("      %s:%d → %s:%d (%s)\n",
				pinhole.RemoteHost, pinhole.RemotePort,
				pinhole.InternalHost, pinhole.InternalPort,
				pinhole.Protocol)
		}

		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    "HIGH",
			Description: "Active IPv6 firewall pinholes detected",
			Details:     fmt.Sprintf("Found %d IPv6 firewall pinholes that may expose internal services to the internet", len(pinholes)),
		})
	} else {
		fmt.Println("    ✓ No IPv6 pinholes found")
	}
}

func getIPv6Pinholes(baseURL string) []common.IPv6Pinhole {
	client := &http.Client{Timeout: 5 * time.Second}
	var pinholes []common.IPv6Pinhole

	for i := 0; i < 20; i++ {
		soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetPinholeEntry xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1">
<UniqueID>%d</UniqueID>
</u:GetPinholeEntry>
</s:Body>
</s:Envelope>`, i)

		req, err := http.NewRequest("POST", baseURL+"/ctl/IPv6FC", strings.NewReader(soapBody))
		if err != nil {
			break
		}

		req.Header.Set("Content-Type", "text/xml; charset=utf-8")
		req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1#GetPinholeEntry"`)

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
		if strings.Contains(content, "RemoteHost") {
			pinhole := parseIPv6Pinhole(content)
			if pinhole.InternalPort > 0 {
				pinholes = append(pinholes, pinhole)
			}
		} else {
			break
		}
	}

	return pinholes
}

func parseIPv6Pinhole(soapResponse string) common.IPv6Pinhole {
	pinhole := common.IPv6Pinhole{}

	if match := regexp.MustCompile(`<RemoteHost>([^<]+)</RemoteHost>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		pinhole.RemoteHost = match[1]
	}
	if match := regexp.MustCompile(`<RemotePort>(\d+)</RemotePort>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			pinhole.RemotePort = port
		}
	}
	if match := regexp.MustCompile(`<InternalClient>([^<]+)</InternalClient>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		pinhole.InternalHost = match[1]
	}
	if match := regexp.MustCompile(`<InternalPort>(\d+)</InternalPort>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		if port, err := strconv.Atoi(match[1]); err == nil {
			pinhole.InternalPort = port
		}
	}
	if match := regexp.MustCompile(`<Protocol>(\d+)</Protocol>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		pinhole.Protocol = match[1]
	}
	if match := regexp.MustCompile(`<LeaseTime>(\d+)</LeaseTime>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		if lease, err := strconv.Atoi(match[1]); err == nil {
			pinhole.LeaseTime = lease
		}
	}

	return pinhole
}

func checkUPnPSecurityIssues(router *common.RouterInfo, baseURL string) {
	fmt.Println("\n  🔒 Checking UPnP security issues...")

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
		fmt.Println("    ⚠️  UPnP allows port mapping to arbitrary internal IPs")

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
		fmt.Println("    ✓ UPnP properly restricts port mappings to requesting device")
	}
}
