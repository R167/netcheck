package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

func checkMDNS(router *RouterInfo) {
	fmt.Println("🔍 Checking mDNS/Bonjour services...")

	if *mdnsFlag {
		// Comprehensive mDNS service discovery
		services := discoverMDNSServices()
		router.MDNSServices = services

		if len(services) > 0 {
			router.MDNSEnabled = true
			fmt.Printf("  📡 Found %d mDNS services\n", len(services))

			for _, service := range services {
				if service.IP != "" && service.Port > 0 {
					fmt.Printf("  🔍 %s (%s) at %s:%d\n", service.Name, service.Type, service.IP, service.Port)
				} else {
					fmt.Printf("  🔍 %s (%s)\n", service.Name, service.Type)
				}

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

// sendMDNSQuery sends a basic mDNS query to detect if the service is running
func sendMDNSQuery() bool {
	conn, err := net.Dial("udp", "224.0.0.251:5353")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Simple mDNS query for _services._dns-sd._udp.local
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
		0x00,       // End of name
		0x00, 0x0C, // Type PTR
		0x00, 0x01, // Class IN
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	return err == nil && n > 12 // Basic validation that we got a response
}

func discoverMDNSServices() []MDNSService {
	// Suppress mdns library log output to reduce noise from IPv6 errors
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var services []MDNSService
	serviceMap := make(map[string]*MDNSService) // Use map to avoid duplicates

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
		"_adisk._tcp.local",
		"_eppc._tcp.local",
		"_sleep-proxy._udp.local",
		"_apple-mobdev2._tcp.local",
		"_airpodd._tcp.local",
		"_homekit-camera._tcp.local",
		"_prometheus-http._tcp.local",
		"_esphomelib._tcp.local",
		"_ipps._tcp.local",
	}

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Channel to collect results
	entriesCh := make(chan *mdns.ServiceEntry, 100)

	// Create a map to track service types for results
	typeMap := make(map[string]string)

	// Query each service type
	for _, serviceType := range serviceTypes {
		// Remove .local suffix for hashicorp/mdns
		cleanServiceType := strings.TrimSuffix(serviceType, ".local")
		typeMap[cleanServiceType] = serviceType

		go func(stype string) {
			params := &mdns.QueryParam{
				Service:             stype,
				Domain:              "local",
				Timeout:             2 * time.Second,
				Entries:             entriesCh,
				WantUnicastResponse: false,
			}
			// Use Query since QueryWithContext isn't available in all versions
			if err := mdns.Query(params); err != nil {
				// Log error if needed, but continue with other queries
			}
		}(cleanServiceType)
	}

	// Collect results with timeout
	timeout := time.After(8 * time.Second)
	for {
		select {
		case entry := <-entriesCh:
			if entry != nil {
				// Create unique key to avoid duplicates
				var ip string
				if entry.AddrV4 != nil {
					ip = entry.AddrV4.String()
				} else if entry.AddrV6 != nil {
					ip = entry.AddrV6.String()
				}

				key := fmt.Sprintf("%s:%s:%d", entry.Name, ip, entry.Port)

				// Only add if it's a new service or we have better information
				if existingService, exists := serviceMap[key]; !exists || existingService.IP == "" {
					var txtData []string
					if entry.Info != "" {
						txtData = strings.Split(entry.Info, "\n")
					}

					// Try to find the original service type from our map
					serviceType := "_unknown._tcp.local"
					for clean, original := range typeMap {
						if strings.Contains(entry.Name, strings.TrimPrefix(clean, "_")) {
							serviceType = original
							break
						}
					}

					service := &MDNSService{
						Name:    entry.Name,
						Type:    serviceType,
						IP:      ip,
						Port:    entry.Port,
						TXTData: txtData,
					}

					// Only add services with valid information
					if service.Name != "" && (service.IP != "" || service.Port > 0) {
						serviceMap[key] = service
					}
				}
			}
		case <-timeout:
			goto done
		case <-ctx.Done():
			goto done
		}
	}

done:
	// Convert map to slice
	for _, service := range serviceMap {
		// Skip entries without proper resolution
		if service.IP == "0.0.0.0" || service.IP == "" {
			// Try to resolve the name if we have it
			if service.Name != "" {
				if ips, err := net.LookupIP(service.Name); err == nil && len(ips) > 0 {
					service.IP = ips[0].String()
				}
			}
		}

		services = append(services, *service)
	}

	return services
}

// checkRiskyMDNSService identifies potentially risky services
func checkRiskyMDNSService(router *RouterInfo, service MDNSService) {
	riskyServices := map[string]string{
		"_ssh._tcp.local":          "SSH service exposed",
		"_ftp._tcp.local":          "FTP service exposed",
		"_telnet._tcp.local":       "Telnet service exposed",
		"_vnc._tcp.local":          "VNC service exposed",
		"_rdp._tcp.local":          "RDP service exposed",
		"_smb._tcp.local":          "SMB/CIFS file sharing exposed",
		"_nfs._tcp.local":          "NFS file sharing exposed",
		"_afpovertcp._tcp.local":   "Apple Filing Protocol exposed",
		"_printer._tcp.local":      "Network printer exposed",
		"_ipp._tcp.local":          "Internet Printing Protocol exposed",
	}

	if description, isRisky := riskyServices[service.Type]; isRisky {
		router.Issues = append(router.Issues, SecurityIssue{
			Severity:    "MEDIUM",
			Description: description + " via mDNS",
			Details:     fmt.Sprintf("Service %s at %s:%d is advertising via mDNS", service.Name, service.IP, service.Port),
		})
	}
}