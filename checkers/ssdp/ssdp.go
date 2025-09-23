package ssdp

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
)

type SSDPChecker struct{}

type SSDPConfig struct {
	IPv4Enabled      bool
	IPv6Enabled      bool
	SearchTargets    []string
	DiscoveryTimeout time.Duration
}

func NewSSDPChecker() checker.Checker {
	return &SSDPChecker{}
}

func (c *SSDPChecker) Name() string {
	return "ssdp"
}

func (c *SSDPChecker) Description() string {
	return "SSDP service discovery (DLNA, UPnP, IoT devices)"
}

func (c *SSDPChecker) Icon() string {
	return "📡"
}

func (c *SSDPChecker) DefaultConfig() checker.CheckerConfig {
	return SSDPConfig{
		IPv4Enabled:      true,
		IPv6Enabled:      true,
		SearchTargets:    []string{"ssdp:all"},
		DiscoveryTimeout: 3 * time.Second,
	}
}

func (c *SSDPChecker) RequiresRouter() bool {
	return true
}

func (c *SSDPChecker) DefaultEnabled() bool {
	return false
}

func (c *SSDPChecker) Run(config checker.CheckerConfig, router *common.RouterInfo) {
	cfg := config.(SSDPConfig)
	discoverSSDPServices(router, cfg)
}

func (c *SSDPChecker) RunStandalone(config checker.CheckerConfig) {
}

func (c *SSDPChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "discover_ssdp_services",
		Description: "Discover network services using SSDP (DLNA media servers, printers, IoT devices)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
				"ipv4_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable IPv4 SSDP discovery",
					"default":     true,
				},
				"ipv6_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable IPv6 SSDP discovery",
					"default":     true,
				},
				"search_targets": map[string]interface{}{
					"type":        "array",
					"description": "SSDP search targets (default: ssdp:all)",
					"items": map[string]interface{}{
						"type": "string",
					},
					"default": []string{"ssdp:all"},
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func discoverSSDPServices(router *common.RouterInfo, cfg SSDPConfig) {
	fmt.Println("\n📡 Discovering SSDP services...")

	var allServices []common.SSDPService

	if cfg.IPv4Enabled {
		ipv4Services := discoverSSDP("239.255.255.250:1900", "IPv4", cfg)
		allServices = append(allServices, ipv4Services...)
	}

	if cfg.IPv6Enabled {
		for _, scope := range []string{"ff02::c", "ff05::c", "ff08::c"} {
			ipv6Services := discoverSSDP(scope+":1900", "IPv6", cfg)
			allServices = append(allServices, ipv6Services...)
		}
	}

	if len(allServices) > 0 {
		router.SSDPEnabled = true
		router.SSDPServices = allServices

		// Group services by device to show all services per device
		deviceGroups := groupServicesByDevice(allServices)
		totalDevices := len(deviceGroups)

		fmt.Printf("  📊 Found %d unique device(s) with %d total services\n", totalDevices, len(allServices))

		// Categorize devices for display
		categorizedDevices := make(map[string][]DeviceGroup)
		for _, group := range deviceGroups {
			category := categorizeService(group.MainService)
			categorizedDevices[category] = append(categorizedDevices[category], group)
		}

		for category, groups := range categorizedDevices {
			fmt.Printf("\n  %s (%d):\n", category, len(groups))
			for _, group := range groups {
				displayDeviceGroup(group)
			}
		}

		// Update router with deduplicated services for security assessment
		var uniqueServices []common.SSDPService
		for _, group := range deviceGroups {
			uniqueServices = append(uniqueServices, group.MainService)
		}
		categorized := categorizeServices(uniqueServices)

		assessSecurityRisks(router, categorized)
	} else {
		fmt.Println("  ℹ️  No SSDP services discovered")
	}
}

func discoverSSDP(multicastAddr string, ipVersion string, cfg SSDPConfig) []common.SSDPService {
	var services []common.SSDPService

	for _, target := range cfg.SearchTargets {
		discovered := performSSDPDiscovery(multicastAddr, target, ipVersion, cfg.DiscoveryTimeout)
		services = append(services, discovered...)
	}

	return services
}

func performSSDPDiscovery(multicastAddr, searchTarget, ipVersion string, timeout time.Duration) []common.SSDPService {
	network := "udp4"
	if ipVersion == "IPv6" {
		network = "udp6"
	}

	localAddr, err := net.ResolveUDPAddr(network, ":0")
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP(network, localAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	maddr, err := net.ResolveUDPAddr(network, multicastAddr)
	if err != nil {
		return nil
	}

	ssdpRequest := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\n"+
		"HOST: %s\r\n"+
		"MAN: \"ssdp:discover\"\r\n"+
		"ST: %s\r\n"+
		"MX: 3\r\n\r\n", multicastAddr, searchTarget)

	_, err = conn.WriteTo([]byte(ssdpRequest), maddr)
	if err != nil {
		return nil
	}

	conn.SetDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 4096)

	var services []common.SSDPService
	seenUSNs := make(map[string]bool)

	for {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}

		response := string(buffer[:n])
		ssdp := parseSSDPResponse(response, ipVersion)
		if ssdp != nil && ssdp.USN != "" && !seenUSNs[ssdp.USN] {
			seenUSNs[ssdp.USN] = true

			if ssdp.Location != "" {
				enrichServiceInfo(ssdp)
			}

			services = append(services, *ssdp)
		}
	}

	return services
}

func parseSSDPResponse(response string, ipVersion string) *common.SSDPService {
	lines := strings.Split(response, "\r\n")
	ssdp := &common.SSDPService{IPVersion: ipVersion}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToUpper(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "LOCATION":
			ssdp.Location = value
		case "SERVER":
			ssdp.Server = value
		case "USN":
			ssdp.USN = value
		case "ST":
			ssdp.DeviceType = value
		}
	}

	if ssdp.Location != "" || ssdp.USN != "" {
		return ssdp
	}
	return nil
}

func enrichServiceInfo(ssdp *common.SSDPService) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ssdp.Location)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var device common.UPnPDevice
		if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
			ssdp.FriendlyName = device.FriendlyName
			ssdp.Manufacturer = device.Manufacturer
			ssdp.ModelName = device.ModelName
		}
	}
}

func categorizeServices(services []common.SSDPService) map[string][]common.SSDPService {
	categories := make(map[string][]common.SSDPService)

	for _, svc := range services {
		category := categorizeService(svc)
		svc.Category = category
		categories[category] = append(categories[category], svc)
	}

	return categories
}

func categorizeService(svc common.SSDPService) string {
	deviceType := strings.ToLower(svc.DeviceType)
	manufacturer := strings.ToLower(svc.Manufacturer)
	friendlyName := strings.ToLower(svc.FriendlyName)

	combined := deviceType + " " + manufacturer + " " + friendlyName

	if strings.Contains(combined, "mediaserver") || strings.Contains(combined, "dlna") {
		return "🎬 Media Servers (DLNA)"
	}
	if strings.Contains(combined, "mediarenderer") || strings.Contains(combined, "chromecast") || strings.Contains(combined, "roku") {
		return "📺 Media Renderers"
	}
	if strings.Contains(combined, "printer") {
		return "🖨️  Printers"
	}
	if strings.Contains(combined, "camera") || strings.Contains(combined, "webcam") {
		return "📷 Cameras"
	}
	if strings.Contains(combined, "nas") || strings.Contains(combined, "storage") {
		return "💾 Network Storage"
	}
	if strings.Contains(combined, "gateway") || strings.Contains(combined, "router") {
		return "🌐 Gateways/Routers"
	}
	if strings.Contains(combined, "light") || strings.Contains(combined, "bulb") || strings.Contains(combined, "switch") {
		return "💡 Smart Home Devices"
	}
	if strings.Contains(combined, "thermostat") || strings.Contains(combined, "sensor") {
		return "🌡️  Sensors/Thermostats"
	}

	return "📦 Other Devices"
}

type DeviceGroup struct {
	MainService common.SSDPService
	AllServices []common.SSDPService
}

func groupServicesByDevice(services []common.SSDPService) []DeviceGroup {
	// Group services by device location and friendly name
	deviceMap := make(map[string]*DeviceGroup)

	for _, svc := range services {
		// Create a device key based on location and friendly name
		deviceKey := ""
		if svc.Location != "" && svc.FriendlyName != "" {
			deviceKey = svc.Location + "::" + svc.FriendlyName
		} else if svc.Location != "" {
			deviceKey = svc.Location
		} else if svc.USN != "" {
			deviceKey = svc.USN
		} else {
			continue // Skip services without meaningful identifiers
		}

		if group, exists := deviceMap[deviceKey]; exists {
			// Add service to existing device group
			group.AllServices = append(group.AllServices, svc)
			// Update main service if this one is more descriptive
			if strings.Contains(svc.DeviceType, "rootdevice") ||
				strings.Contains(svc.DeviceType, "InternetGatewayDevice") ||
				strings.Contains(svc.DeviceType, "NAS") {
				group.MainService = svc
			}
		} else {
			// Create new device group
			deviceMap[deviceKey] = &DeviceGroup{
				MainService: svc,
				AllServices: []common.SSDPService{svc},
			}
		}
	}

	// Convert map to slice
	var groups []DeviceGroup
	for _, group := range deviceMap {
		groups = append(groups, *group)
	}

	return groups
}

func displayDeviceGroup(group DeviceGroup) {
	svc := group.MainService

	// Main device info
	if svc.FriendlyName != "" {
		fmt.Printf("    • %s", svc.FriendlyName)
		if svc.ModelName != "" && svc.ModelName != svc.FriendlyName {
			fmt.Printf(" (%s)", svc.ModelName)
		}
	} else if svc.ModelName != "" {
		fmt.Printf("    • %s", svc.ModelName)
	} else {
		fmt.Printf("    • %s", svc.DeviceType)
	}

	// Add manufacturer if available and different from friendly name
	if svc.Manufacturer != "" && !strings.Contains(strings.ToLower(svc.FriendlyName), strings.ToLower(svc.Manufacturer)) {
		fmt.Printf(" [%s]", svc.Manufacturer)
	}
	fmt.Println()

	// Location URL (important for security assessment)
	if svc.Location != "" {
		fmt.Printf("      🔗 %s\n", svc.Location)
	}

	// Server information (reveals software versions)
	if svc.Server != "" {
		fmt.Printf("      🖥️  Server: %s\n", svc.Server)
	}

	// Show all services this device offers
	if len(group.AllServices) > 1 {
		fmt.Printf("      📱 Services (%d):\n", len(group.AllServices))
		for _, serviceSvc := range group.AllServices {
			if serviceSvc.DeviceType != "" && serviceSvc.DeviceType != "upnp:rootdevice" && serviceSvc.DeviceType != "ssdp:all" {
				// Clean up service type for display
				serviceType := serviceSvc.DeviceType
				if strings.Contains(serviceType, "urn:schemas-upnp-org:service:") {
					serviceType = strings.ReplaceAll(serviceType, "urn:schemas-upnp-org:service:", "")
					serviceType = strings.ReplaceAll(serviceType, ":1", "")
					serviceType = strings.ReplaceAll(serviceType, ":2", "")
				}
				if strings.Contains(serviceType, "urn:schemas-upnp-org:device:") {
					serviceType = strings.ReplaceAll(serviceType, "urn:schemas-upnp-org:device:", "")
					serviceType = strings.ReplaceAll(serviceType, ":1", "")
					serviceType = strings.ReplaceAll(serviceType, ":2", "")
				}
				fmt.Printf("        - %s\n", serviceType)
			}
		}
	}

	// IP version
	if svc.IPVersion != "" {
		fmt.Printf("      🌐 %s\n", svc.IPVersion)
	}
	fmt.Println()
}

func assessSecurityRisks(router *common.RouterInfo, categorized map[string][]common.SSDPService) {
	mediaServers := categorized["🎬 Media Servers (DLNA)"]
	if len(mediaServers) > 0 {
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityLow,
			Description: fmt.Sprintf("DLNA media servers discovered (%d)", len(mediaServers)),
			Details:     "DLNA servers may expose media files to the network. Ensure access controls are properly configured.",
		})
	}

	cameras := categorized["📷 Cameras"]
	if len(cameras) > 0 {
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityMedium,
			Description: fmt.Sprintf("Network cameras discovered (%d)", len(cameras)),
			Details:     "Network cameras may have default credentials or known vulnerabilities. Update firmware and change default passwords.",
		})
	}

	nas := categorized["💾 Network Storage"]
	if len(nas) > 0 {
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityMedium,
			Description: fmt.Sprintf("Network storage devices discovered (%d)", len(nas)),
			Details:     "NAS devices may expose sensitive data. Ensure proper access controls and encryption are enabled.",
		})
	}

	smartHome := categorized["💡 Smart Home Devices"]
	if len(smartHome) > 0 {
		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityLow,
			Description: fmt.Sprintf("Smart home devices discovered (%d)", len(smartHome)),
			Details:     "IoT devices may have security vulnerabilities. Keep firmware updated and isolate on separate network if possible.",
		})
	}
}
