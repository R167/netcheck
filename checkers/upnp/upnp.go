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

	"github.com/R167/netcheck/checkers"
	"github.com/R167/netcheck/checkers/common"
)

type UPnPChecker struct{}

type UPnPConfig struct {
	EnumerateMappings bool
}

func NewUPnPChecker() checkers.Checker {
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

func (c *UPnPChecker) DefaultConfig() checkers.CheckerConfig {
	return UPnPConfig{
		EnumerateMappings: true,
	}
}

func (c *UPnPChecker) RequiresRouter() bool {
	return true
}

func (c *UPnPChecker) DefaultEnabled() bool {
	return true
}

func (c *UPnPChecker) Run(config checkers.CheckerConfig, router *common.RouterInfo) {
	cfg := config.(UPnPConfig)
	checkUPnP(router, cfg)
}

func (c *UPnPChecker) RunStandalone(config checkers.CheckerConfig) {
}

func (c *UPnPChecker) MCPToolDefinition() *checkers.MCPTool {
	return &checkers.MCPTool{
		Name:        "check_upnp",
		Description: "Check for UPnP services and enumerate port mappings",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
				"enumerate_mappings": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to enumerate active port mappings",
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

			if cfg.EnumerateMappings {
				checkUPnPPortMappings(router, upnpInfo.Location)
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