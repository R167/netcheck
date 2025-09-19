package main

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
)

func isPortOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), PortTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkUPnP(router *RouterInfo) {
	fmt.Println("\n🔍 Checking UPnP services...")

	// Check for UPnP SSDP discovery
	upnpInfo := checkSSDPMulticast()
	if upnpInfo != nil {
		router.UPnPEnabled = true
		fmt.Println("  📡 UPnP SSDP discovered")
		fmt.Printf("  🔗 Location: %s\n", upnpInfo.Location)
		fmt.Printf("  🖥️  Server: %s\n", upnpInfo.Server)

		// Try to get device description from discovered location
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

			// Check for exposed port mappings
			checkUPnPPortMappings(router, upnpInfo.Location)
		}

		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: "UPnP service is enabled",
			Details:     "UPnP can expose internal services and allow port forwarding. Ensure it's properly configured.",
		})
	} else {
		// Fallback: Check for UPnP IGD on common ports
		upnpPorts := []int{1900, 5000, 49152, 49153, 49154}
		for _, port := range upnpPorts {
			if isPortOpen(router.IP, port) {
				router.UPnPEnabled = true
				fmt.Printf("  ✅ UPnP service on port %d\n", port)

				// Try to get device description
				if desc := getUPnPDescription(router.IP, port); desc != nil {
					fmt.Printf("  📄 Device: %s (%s)\n", desc.FriendlyName, desc.Manufacturer)
					if desc.ModelName != "" {
						router.Model = desc.ModelName
					}
				}
			}
		}
	}

	if !router.UPnPEnabled {
		fmt.Println("  ✅ No UPnP services detected")
	}
}

func checkSSDPMulticast() *SSDPResponse {
	// Create a UDP socket to send SSDP multicast
	localAddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send SSDP M-SEARCH
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

	// Set timeout and read responses
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 2048)

	// Try to read multiple responses in case there are multiple devices
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

func parseSSDPResponse(response string) *SSDPResponse {
	lines := strings.Split(response, "\r\n")
	ssdp := &SSDPResponse{}

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

func getUPnPDescription(ip string, port int) *UPnPDevice {
	client := &http.Client{Timeout: 3 * time.Second}

	// Common UPnP description paths
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
			var device UPnPDevice
			if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
				return &device
			}
		}
	}
	return nil
}

func getUPnPDescriptionFromURL(url string) *UPnPDevice {
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var device UPnPDevice
		if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
			return &device
		}
	}
	return nil
}

func checkUPnPPortMappings(router *RouterInfo, baseURL string) {
	// Extract base URL for SOAP requests
	// Example: http://10.44.10.1:33163/rootDesc.xml -> http://10.44.10.1:33163
	parts := strings.Split(baseURL, "/")
	if len(parts) < 4 {
		return
	}
	soapBaseURL := strings.Join(parts[:3], "/")

	// Try to get port mappings
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

		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "HIGH",
			Description: "Active UPnP port mappings detected",
			Details:     fmt.Sprintf("Found %d active port forwarding rules that may expose internal services", len(mappings)),
		})
	}
}

func getPortMappings(baseURL string) []PortMapping {
	client := &http.Client{Timeout: 5 * time.Second}
	var mappings []PortMapping

	// Try to enumerate port mappings
	for i := 0; i < 50; i++ { // Check first 50 entries
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

		// Parse the SOAP response (simplified)
		content := string(body)
		if strings.Contains(content, "NewExternalPort") {
			mapping := parsePortMapping(content)
			if mapping.ExternalPort > 0 {
				mappings = append(mappings, mapping)
			}
		} else {
			break // No more mappings
		}
	}

	return mappings
}

func parsePortMapping(soapResponse string) PortMapping {
	mapping := PortMapping{}

	// Extract values using simple string matching (could be improved with proper XML parsing)
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
