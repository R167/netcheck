package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func checkMDNS(router *RouterInfo) {
	fmt.Println("\n🔍 Checking mDNS/Bonjour services...")

	if *mdnsFlag {
		// Comprehensive mDNS service discovery
		services := discoverMDNSServices()
		router.MDNSServices = services

		if len(services) > 0 {
			router.MDNSEnabled = true
			fmt.Printf("  📡 Found %d mDNS services\n", len(services))

			for _, service := range services {
				fmt.Printf("  🔍 %s (%s) at %s:%d\n", service.Name, service.Type, service.IP, service.Port)

				// Check for potentially risky services
				checkRiskyMDNSService(router, service)
			}

			router.Issues = append(router.Issues, SecurityIssue{
				Severity:    "LOW",
				Description: "mDNS services discovered",
				Details:     fmt.Sprintf("Found %d services advertising via mDNS. Review if all should be exposed.", len(services)),
			})
		} else {
			fmt.Println("  ✅ No mDNS services discovered")
		}
	} else {
		// Basic mDNS detection
		if sendMDNSQuery() {
			router.MDNSEnabled = true
			fmt.Println("  📡 mDNS service detected (use --mdns for detailed scan)")

			router.Issues = append(router.Issues, SecurityIssue{
				Severity:    "LOW",
				Description: "mDNS service is enabled",
				Details:     "mDNS can expose device information to the local network. Use --mdns flag for detailed discovery.",
			})
		} else {
			fmt.Println("  ✅ No mDNS service detected")
		}
	}
}

func sendMDNSQuery() bool {
	// Send mDNS query for _services._dns-sd._udp.local
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return false
	}

	localAddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		return false
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Simple mDNS query for services
	query := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query: _services._dns-sd._udp.local
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00, // End of name
		0x00, 0x0C, // Type PTR
		0x00, 0x01, // Class IN
	}

	_, err = conn.WriteTo(query, addr)
	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buffer)

	return err == nil && n > 12 // Basic validation that we got a response
}

func discoverMDNSServices() []MDNSService {
	var services []MDNSService

	// Common service types to query
	serviceTypes := []string{
		"_services._dns-sd._udp.local",
		"_http._tcp.local",
		"_https._tcp.local",
		"_ssh._tcp.local",
		"_ftp._tcp.local",
		"_smb._tcp.local",
		"_afpovertcp._tcp.local",
		"_nfs._tcp.local",
		"_printer._tcp.local",
		"_ipp._tcp.local",
		"_airplay._tcp.local",
		"_raop._tcp.local",
		"_chromecast._tcp.local",
		"_googlecast._tcp.local",
		"_homekit._tcp.local",
		"_hap._tcp.local",
		"_spotify-connect._tcp.local",
		"_sonos._tcp.local",
		"_workstation._tcp.local",
		"_device-info._tcp.local",
		"_companion-link._tcp.local",
		"_rdp._tcp.local",
		"_vnc._tcp.local",
		"_telnet._tcp.local",
		"_daap._tcp.local",
		"_dpap._tcp.local",
		"_eppc._tcp.local",
	}

	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return services
	}

	localAddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		return services
	}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return services
	}
	defer conn.Close()

	// Query each service type
	for _, serviceType := range serviceTypes {
		query := buildMDNSQuery(serviceType)
		conn.WriteTo(query, addr)
	}

	// Collect responses for a few seconds
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	responses := make(map[string]MDNSService)

	for {
		buffer := make([]byte, 4096)
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}

		if parsedServices := parseMDNSResponse(buffer[:n]); len(parsedServices) > 0 {
			for _, service := range parsedServices {
				key := fmt.Sprintf("%s:%s:%d", service.Name, service.IP, service.Port)
				responses[key] = service
			}
		}
	}

	// Convert map to slice
	for _, service := range responses {
		services = append(services, service)
	}

	return services
}

func buildMDNSQuery(serviceType string) []byte {
	query := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
	}

	// Encode the service type name
	parts := strings.Split(serviceType, ".")
	for _, part := range parts {
		if part != "" {
			query = append(query, byte(len(part)))
			query = append(query, []byte(part)...)
		}
	}
	query = append(query, 0x00) // End of name

	query = append(query, 0x00, 0x0C) // Type PTR
	query = append(query, 0x00, 0x01) // Class IN

	return query
}

func parseMDNSResponse(data []byte) []MDNSService {
	var services []MDNSService

	if len(data) < 12 {
		return services
	}

	// Skip header
	offset := 12

	// Parse questions (skip them)
	questions := int(data[4])<<8 | int(data[5])
	for i := 0; i < questions && offset < len(data); i++ {
		// Skip name
		for offset < len(data) && data[offset] != 0 {
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(data[offset]) + 1
		}
		if offset < len(data) {
			offset++ // Skip null terminator
		}
		offset += 4 // Skip type and class
	}

	// Parse answers
	answers := int(data[6])<<8 | int(data[7])
	for i := 0; i < answers && offset < len(data); i++ {
		service := parseMDNSRecord(data, &offset)
		if service.Name != "" {
			services = append(services, service)
		}
	}

	return services
}

func parseMDNSRecord(data []byte, offset *int) MDNSService {
	service := MDNSService{}

	if *offset >= len(data) {
		return service
	}

	// Skip name
	startOffset := *offset
	for *offset < len(data) && data[*offset] != 0 {
		if data[*offset]&0xC0 == 0xC0 {
			*offset += 2
			break
		}
		*offset += int(data[*offset]) + 1
	}
	if *offset < len(data) {
		*offset++ // Skip null terminator
	}

	if *offset+10 > len(data) {
		return service
	}

	recordType := int(data[*offset])<<8 | int(data[*offset+1])
	*offset += 2
	recordClass := int(data[*offset])<<8 | int(data[*offset+1])
	*offset += 2
	ttl := int(data[*offset])<<24 | int(data[*offset+1])<<16 | int(data[*offset+2])<<8 | int(data[*offset+3])
	*offset += 4
	dataLength := int(data[*offset])<<8 | int(data[*offset+1])
	*offset += 2

	_ = recordClass
	_ = ttl

	if *offset+dataLength > len(data) {
		return service
	}

	// Parse based on record type
	switch recordType {
	case 1: // A record
		if dataLength == 4 {
			service.IP = fmt.Sprintf("%d.%d.%d.%d", data[*offset], data[*offset+1], data[*offset+2], data[*offset+3])
			service.Name = extractName(data, startOffset)
		}
	case 28: // AAAA record
		if dataLength == 16 {
			// IPv6 address
			service.Name = extractName(data, startOffset)
		}
	case 12: // PTR record
		service.Type = extractName(data, startOffset)
		service.Name = extractName(data, *offset)
	case 33: // SRV record
		if dataLength >= 6 {
			service.Port = int(data[*offset+4])<<8 | int(data[*offset+5])
			service.Name = extractName(data, startOffset)
		}
	case 16: // TXT record
		service.Name = extractName(data, startOffset)
		// Parse TXT data (simplified)
		txtOffset := *offset
		for txtOffset < *offset+dataLength {
			txtLen := int(data[txtOffset])
			if txtLen > 0 && txtOffset+txtLen < len(data) {
				txt := string(data[txtOffset+1 : txtOffset+1+txtLen])
				service.TXTData = append(service.TXTData, txt)
			}
			txtOffset += txtLen + 1
		}
	}

	*offset += dataLength
	return service
}

func extractName(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}

	var name strings.Builder
	jumped := false
	jumpOffset := 0

	for offset < len(data) {
		length := data[offset]

		if length == 0 {
			break
		}

		// Handle compression
		if length&0xC0 == 0xC0 {
			if !jumped {
				jumpOffset = offset + 2
				jumped = true
			}
			offset = int(data[offset+1]) | ((int(length) & 0x3F) << 8)
			continue
		}

		offset++
		if offset+int(length) > len(data) {
			break
		}

		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[offset : offset+int(length)])
		offset += int(length)
	}

	if jumped {
		offset = jumpOffset
	}

	return name.String()
}

func checkRiskyMDNSService(router *RouterInfo, service MDNSService) {
	riskyServices := map[string]string{
		"_ssh._tcp.local":     "SSH service exposed",
		"_ftp._tcp.local":     "FTP service exposed",
		"_telnet._tcp.local":  "Telnet service exposed",
		"_smb._tcp.local":     "SMB/CIFS file sharing exposed",
		"_nfs._tcp.local":     "NFS file sharing exposed",
		"_vnc._tcp.local":     "VNC remote desktop exposed",
		"_rdp._tcp.local":     "RDP remote desktop exposed",
		"_printer._tcp.local": "Network printer exposed",
	}

	if description, exists := riskyServices[service.Type]; exists {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: description + " via mDNS",
			Details:     fmt.Sprintf("Service %s at %s:%d is advertising via mDNS", service.Name, service.IP, service.Port),
		})
	}
}