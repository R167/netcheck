package mdns_listen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/mdns"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type MDNSListenChecker struct{}

type MDNSListenConfig struct {
	Timeout time.Duration
	ReQuery bool // If true, actively query for services discovered in queries
}

// MDNSQuery represents a captured mDNS query
type MDNSQuery struct {
	SourceIP  string
	Timestamp time.Time
	Questions []string
}

func NewMDNSListenChecker() checker.Checker {
	return &MDNSListenChecker{}
}

func (c *MDNSListenChecker) Name() string {
	return "mdns-listen"
}

func (c *MDNSListenChecker) Description() string {
	return "Passive monitoring of mDNS queries on the network"
}

func (c *MDNSListenChecker) Icon() string {
	return "👂"
}

func (c *MDNSListenChecker) DefaultConfig() checker.CheckerConfig {
	return MDNSListenConfig{
		Timeout: 10 * time.Second,
		ReQuery: false,
	}
}

func (c *MDNSListenChecker) RequiresRouter() bool {
	return false
}

func (c *MDNSListenChecker) DefaultEnabled() bool {
	return false // Not enabled by default as it requires listening time
}

func (c *MDNSListenChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyNetwork}
}

func (c *MDNSListenChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	// This is a standalone checker - no router-based functionality
}

func (c *MDNSListenChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
	cfg := config.(MDNSListenConfig)
	listenForMDNSQueries(cfg, out)
}

func (c *MDNSListenChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "mdns_listen",
		Description: "Passively monitor mDNS queries to identify active service discovery on the network",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"timeout": map[string]interface{}{
					"type":        "number",
					"description": "Listening timeout in seconds",
					"default":     10,
				},
				"requery": map[string]interface{}{
					"type":        "boolean",
					"description": "Actively query for services discovered in captured queries",
					"default":     false,
				},
			},
			"required": []string{},
		},
	}
}

func listenForMDNSQueries(cfg MDNSListenConfig, out output.Output) {
	out.Section("👂", "Listening for mDNS queries...")
	out.Info("Monitoring network for %v...", cfg.Timeout)

	// mDNS uses multicast address 224.0.0.251 on port 5353
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		out.Error("Failed to resolve mDNS address: %v", err)
		return
	}

	// Listen on all interfaces
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		out.Error("Failed to listen for mDNS queries: %v", err)
		out.Info("Note: This check requires network privileges. Try running with sudo/admin rights.")
		return
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))

	queries := make(map[string]*MDNSQuery) // Key: sourceIP
	buffer := make([]byte, 1500)           // MTU-sized buffer

	startTime := time.Now()
	for time.Since(startTime) < cfg.Timeout {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}

		// Parse the mDNS packet
		if query := parseMDNSPacket(buffer[:n], remoteAddr.IP.String()); query != nil {
			// Aggregate queries by source IP
			key := query.SourceIP
			if existing, exists := queries[key]; exists {
				// Add new questions to existing entry
				existing.Questions = append(existing.Questions, query.Questions...)
			} else {
				queries[key] = query
			}
		}
	}

	// Report findings
	if len(queries) == 0 {
		out.Success("No mDNS queries detected during monitoring period")
		return
	}

	out.Info("Detected mDNS queries from %d source(s)", len(queries))

	// Collect all unique service queries across all sources
	allUniqueQuestions := make(map[string]bool)

	for sourceIP, query := range queries {
		out.Info("")
		out.Info("Source: %s", sourceIP)

		// Deduplicate questions
		uniqueQuestions := make(map[string]bool)
		for _, q := range query.Questions {
			uniqueQuestions[q] = true
			allUniqueQuestions[q] = true
		}

		if len(uniqueQuestions) > 0 {
			out.Info("  Queried services:")
			for q := range uniqueQuestions {
				out.Info("    • %s", q)
			}
		}
	}

	// If ReQuery is enabled, actively discover these services
	if cfg.ReQuery && len(allUniqueQuestions) > 0 {
		out.Info("")
		out.Section("🔍", "Re-querying discovered services...")
		discoveredServices := requeryServices(allUniqueQuestions, out)

		if len(discoveredServices) > 0 {
			out.Info("Found %d responding device(s):", len(discoveredServices))
			for _, service := range discoveredServices {
				if service.IP != "" && service.Port > 0 {
					out.Info("  🖥️  %s (%s) at %s:%d", service.Name, service.Type, service.IP, service.Port)
					if len(service.TXTData) > 0 {
						out.Info("      TXT: %s", strings.Join(service.TXTData, ", "))
					}
				} else if service.IP != "" {
					out.Info("  🖥️  %s (%s) at %s", service.Name, service.Type, service.IP)
				} else {
					out.Info("  🖥️  %s (%s)", service.Name, service.Type)
				}
			}
		} else {
			out.Info("No devices responded to the queried services")
		}
	}

	// Security assessment
	out.Info("")
	out.Info("🛡️  Security Assessment:")
	out.Info("⚠️  Active service discovery detected on the network")
	out.Info("   • %d device(s) are actively searching for mDNS services", len(queries))
	out.Info("   • This reveals devices performing network reconnaissance")
	out.Info("")
	out.Info("💡 Recommendations:")
	out.Info("   • Review which devices are performing service discovery")
	out.Info("   • Unexpected queries may indicate unauthorized devices or malware")
	out.Info("   • Consider network segmentation for sensitive devices")
}

// requeryServices actively queries for the services discovered during passive listening
func requeryServices(serviceQueries map[string]bool, out output.Output) []common.MDNSService {
	// Suppress mdns library log output
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var services []common.MDNSService
	serviceMap := make(map[string]*common.MDNSService)

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Channel to collect results
	entriesCh := make(chan *mdns.ServiceEntry, 100)

	// Query each service that was discovered in queries
	queriedServices := make([]string, 0, len(serviceQueries))
	for serviceName := range serviceQueries {
		queriedServices = append(queriedServices, serviceName)
	}

	out.Info("Actively querying %d unique service(s)...", len(queriedServices))

	for _, serviceName := range queriedServices {
		// Parse the service name to extract service type and domain
		// Format can be: "_http._tcp.local", "device.local", etc.
		cleanServiceName := serviceName

		// Determine if this is a service type query or hostname query
		var serviceType string
		var domain string

		if strings.Contains(serviceName, "._tcp.") || strings.Contains(serviceName, "._udp.") {
			// This is a service type query (e.g., "_http._tcp.local")
			// Remove .local suffix for hashicorp/mdns
			cleanServiceName = strings.TrimSuffix(serviceName, ".local")

			// Split into service type and domain
			parts := strings.Split(cleanServiceName, ".")
			if len(parts) >= 2 {
				// Reconstruct service type (e.g., "_http._tcp")
				serviceType = strings.Join(parts[:len(parts)], ".")
				domain = "local"
			} else {
				serviceType = cleanServiceName
				domain = "local"
			}
		} else if strings.HasSuffix(serviceName, ".local") {
			// This is a hostname query (e.g., "mydevice.local")
			// We can try to discover it using the generic service query
			hostname := strings.TrimSuffix(serviceName, ".local")
			serviceType = hostname
			domain = "local"
		} else {
			// Unknown format, skip
			continue
		}

		// Launch goroutine to query this service
		go func(stype, originalName string) {
			params := &mdns.QueryParam{
				Service:             stype,
				Domain:              domain,
				Timeout:             2 * time.Second,
				Entries:             entriesCh,
				WantUnicastResponse: false,
			}
			if err := mdns.Query(params); err != nil {
				// Silently continue on error
			}
		}(serviceType, serviceName)
	}

	// Collect results with timeout
	timeout := time.After(6 * time.Second)
	done := false

	for !done {
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

					// Try to match the service type from our original queries
					matchedType := "_unknown._tcp.local"
					for originalService := range serviceQueries {
						if strings.Contains(entry.Name, strings.TrimSuffix(originalService, ".local")) ||
							strings.Contains(originalService, strings.TrimSuffix(entry.Name, ".local")) {
							matchedType = originalService
							break
						}
					}

					service := &common.MDNSService{
						Name:    entry.Name,
						Type:    matchedType,
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
			done = true
		case <-ctx.Done():
			done = true
		}
	}

	// Convert map to slice
	for _, service := range serviceMap {
		// Try to resolve hostname if IP is missing
		if service.IP == "0.0.0.0" || service.IP == "" {
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

// parseMDNSPacket parses a DNS packet and extracts query information
func parseMDNSPacket(data []byte, sourceIP string) *MDNSQuery {
	// DNS packet minimum size is 12 bytes (header)
	if len(data) < 12 {
		return nil
	}

	// Parse DNS header
	// Flags are in bytes 2-3
	flags := binary.BigEndian.Uint16(data[2:4])

	// Check if this is a query (QR bit = 0) and not a response
	// QR bit is the most significant bit of the flags
	isQuery := (flags & 0x8000) == 0
	if !isQuery {
		return nil
	}

	// Get question count from bytes 4-5
	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 {
		return nil
	}

	query := &MDNSQuery{
		SourceIP:  sourceIP,
		Timestamp: time.Now(),
		Questions: make([]string, 0),
	}

	// Parse questions section (starts at byte 12)
	offset := 12
	for i := uint16(0); i < qdcount && offset < len(data); i++ {
		name, newOffset := parseDNSName(data, offset)
		if name != "" {
			query.Questions = append(query.Questions, name)
		}

		// Skip QTYPE (2 bytes) and QCLASS (2 bytes)
		offset = newOffset + 4
		if offset > len(data) {
			break
		}
	}

	if len(query.Questions) > 0 {
		return query
	}
	return nil
}

// parseDNSName parses a DNS name from the packet data
func parseDNSName(data []byte, offset int) (string, int) {
	var parts []string
	jumped := false
	originalOffset := offset
	maxJumps := 5 // Prevent infinite loops

	for jumps := 0; offset < len(data) && jumps < maxJumps; {
		length := int(data[offset])

		// Check for compression pointer (top 2 bits are 11)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			// Pointer to another location in the packet
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			jumps++
			continue
		}

		// End of name
		if length == 0 {
			offset++
			break
		}

		// Regular label
		if offset+1+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	if jumped {
		return strings.Join(parts, "."), originalOffset
	}
	return strings.Join(parts, "."), offset
}
