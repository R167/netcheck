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

// Network and protocol constants
const (
	// mdnsBufferSize is the buffer size for UDP packets, matching standard Ethernet MTU
	mdnsBufferSize = 1500

	// maxDNSCompressionJumps limits pointer following in DNS name parsing to prevent infinite loops
	maxDNSCompressionJumps = 5
)

// Timeout constants for service re-query operations
const (
	// requeryContextTimeout is the maximum time for the entire re-query operation
	requeryContextTimeout = 8 * time.Second

	// individualQueryTimeout is how long each mDNS service query waits for responses
	individualQueryTimeout = 2 * time.Second

	// serviceChannelBuffer is the buffer size for collecting mDNS service entries
	serviceChannelBuffer = 100
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
	cfg, ok := config.(MDNSListenConfig)
	if !ok {
		out.Error("Invalid configuration type for mdns-listen checker")
		return
	}
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

	// Listen on all interfaces for mDNS multicast traffic
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		out.Error("Failed to listen for mDNS queries: %v", err)
		out.Info("Note: This check requires network privileges. Try running with sudo/admin rights.")
		return
	}
	defer conn.Close()

	// Capture mDNS queries from the network
	queries := captureQueriesFromNetwork(conn, cfg.Timeout, out)

	// Report what queries were detected
	reportCapturedQueries(queries, out)

	// If re-query is enabled, actively discover the services that were queried
	if cfg.ReQuery {
		allUniqueServices := collectUniqueServiceNames(queries)
		if len(allUniqueServices) > 0 {
			out.Info("")
			out.Section("🔍", "Re-querying discovered services...")
			discoveredServices := requeryServices(allUniqueServices, out)
			reportDiscoveredServices(discoveredServices, out)
		}
	}

	// Provide security assessment based on findings
	outputSecurityAssessment(len(queries), out)
}

// captureQueriesFromNetwork listens on the UDP connection for mDNS queries and aggregates them by source IP.
// It returns a map of source IP addresses to the queries they sent.
func captureQueriesFromNetwork(conn *net.UDPConn, timeout time.Duration, out output.Output) map[string]*MDNSQuery {
	queries := make(map[string]*MDNSQuery)
	buffer := make([]byte, mdnsBufferSize)

	// Set read deadline to stop listening after timeout
	conn.SetReadDeadline(time.Now().Add(timeout))

	startTime := time.Now()
	for time.Since(startTime) < timeout {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout reached - this is expected, exit loop
				break
			}
			// Other network errors - log and continue
			out.Debug("Error reading UDP packet: %v", err)
			continue
		}

		// Parse the mDNS packet to extract query information
		if query := parseMDNSPacket(buffer[:n], remoteAddr.IP.String()); query != nil {
			sourceIP := query.SourceIP

			// Aggregate queries from the same source
			if existing, exists := queries[sourceIP]; exists {
				existing.Questions = append(existing.Questions, query.Questions...)
			} else {
				queries[sourceIP] = query
			}
		}
	}

	return queries
}

// reportCapturedQueries outputs the captured mDNS queries organized by source IP.
func reportCapturedQueries(queries map[string]*MDNSQuery, out output.Output) {
	if len(queries) == 0 {
		out.Success("No mDNS queries detected during monitoring period")
		return
	}

	out.Info("Detected mDNS queries from %d source(s)", len(queries))

	for sourceIP, query := range queries {
		out.Info("")
		out.Info("Source: %s", sourceIP)

		// Deduplicate questions from this source
		uniqueQuestions := make(map[string]bool)
		for _, q := range query.Questions {
			uniqueQuestions[q] = true
		}

		if len(uniqueQuestions) > 0 {
			out.Info("  Queried services:")
			for q := range uniqueQuestions {
				out.Info("    • %s", q)
			}
		}
	}
}

// collectUniqueServiceNames extracts all unique service names from captured queries.
// Returns a set (map[string]bool) of unique service names across all sources.
func collectUniqueServiceNames(queries map[string]*MDNSQuery) map[string]bool {
	uniqueServices := make(map[string]bool)

	for _, query := range queries {
		for _, serviceName := range query.Questions {
			uniqueServices[serviceName] = true
		}
	}

	return uniqueServices
}

// reportDiscoveredServices outputs information about services discovered during re-query.
func reportDiscoveredServices(services []common.MDNSService, out output.Output) {
	if len(services) == 0 {
		out.Info("No devices responded to the queried services")
		return
	}

	out.Info("Found %d responding device(s):", len(services))
	for _, service := range services {
		out.Info("  %s", formatServiceInfo(service))
		if len(service.TXTData) > 0 {
			out.Info("      TXT: %s", strings.Join(service.TXTData, ", "))
		}
	}
}

// formatServiceInfo formats service information for display, including location details if available.
func formatServiceInfo(service common.MDNSService) string {
	location := ""
	if service.IP != "" && service.Port > 0 {
		location = fmt.Sprintf(" at %s:%d", service.IP, service.Port)
	} else if service.IP != "" {
		location = fmt.Sprintf(" at %s", service.IP)
	}
	return fmt.Sprintf("🖥️  %s (%s)%s", service.Name, service.Type, location)
}

// outputSecurityAssessment provides security analysis and recommendations based on detected activity.
func outputSecurityAssessment(deviceCount int, out output.Output) {
	if deviceCount == 0 {
		return
	}

	out.Info("")
	out.Info("🛡️  Security Assessment:")
	out.Info("⚠️  Active service discovery detected on the network")
	out.Info("   • %d device(s) are actively searching for mDNS services", deviceCount)
	out.Info("   • This reveals devices performing network reconnaissance")
	out.Info("")
	out.Info("💡 Recommendations:")
	out.Info("   • Review which devices are performing service discovery")
	out.Info("   • Unexpected queries may indicate unauthorized devices or malware")
	out.Info("   • Consider network segmentation for sensitive devices")
}

// requeryServices actively queries for the services discovered during passive listening.
// It uses the hashicorp/mdns library to perform standard mDNS queries and collect responses.
func requeryServices(serviceQueries map[string]bool, out output.Output) []common.MDNSService {
	// Suppress mdns library log output to reduce noise
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	// Set up context with timeout for the entire re-query operation
	ctx, cancel := context.WithTimeout(context.Background(), requeryContextTimeout)
	defer cancel()

	// Channel to collect service entries as they are discovered
	serviceEntriesChannel := make(chan *mdns.ServiceEntry, serviceChannelBuffer)

	// Launch queries for all discovered services
	out.Info("Actively querying %d unique service(s)...", len(serviceQueries))
	launchServiceQueries(serviceQueries, serviceEntriesChannel)

	// Collect and aggregate responses until context timeout
	serviceMap := collectServiceResponses(ctx, serviceEntriesChannel, serviceQueries)

	// Convert aggregated map to list and resolve any missing IPs
	return convertToServiceList(serviceMap)
}

// launchServiceQueries starts goroutines to query each discovered service.
// Each query runs independently and sends results to the provided channel.
func launchServiceQueries(serviceQueries map[string]bool, entriesChannel chan *mdns.ServiceEntry) {
	for serviceName := range serviceQueries {
		// Parse the service name to determine how to query it
		serviceType, domain, valid := parseServiceName(serviceName)
		if !valid {
			continue
		}

		// Launch a goroutine to query this service
		go queryService(serviceType, domain, entriesChannel)
	}
}

// parseServiceName extracts service type and domain from mDNS service name.
// Supports service type queries ("_http._tcp.local") and hostname queries ("device.local").
// Returns the parsed components and a validity flag.
func parseServiceName(serviceName string) (serviceType, domain string, valid bool) {
	// Service type query: "_http._tcp.local" or "_printer._udp.local"
	if strings.Contains(serviceName, "._tcp.") || strings.Contains(serviceName, "._udp.") {
		// Remove .local suffix for hashicorp/mdns library
		cleanName := strings.TrimSuffix(serviceName, ".local")
		return cleanName, "local", true
	}

	// Hostname query: "mydevice.local"
	if strings.HasSuffix(serviceName, ".local") {
		hostname := strings.TrimSuffix(serviceName, ".local")
		return hostname, "local", true
	}

	// Unknown format
	return "", "", false
}

// queryService sends an mDNS query for a specific service type and sends results to the channel.
func queryService(serviceType, domain string, entriesChannel chan *mdns.ServiceEntry) {
	params := &mdns.QueryParam{
		Service:             serviceType,
		Domain:              domain,
		Timeout:             individualQueryTimeout,
		Entries:             entriesChannel,
		WantUnicastResponse: false,
	}

	if err := mdns.Query(params); err != nil {
		// Query failed - this is common for services that don't exist
		// No action needed as we're collecting all available responses
	}
}

// collectServiceResponses gathers mDNS responses from the channel until context cancellation.
// It deduplicates services and matches them to their original query types.
func collectServiceResponses(ctx context.Context, entriesChannel chan *mdns.ServiceEntry, serviceQueries map[string]bool) map[string]*common.MDNSService {
	serviceMap := make(map[string]*common.MDNSService)

	for {
		select {
		case entry := <-entriesChannel:
			if entry != nil {
				processServiceEntry(entry, serviceQueries, serviceMap)
			}

		case <-ctx.Done():
			// Context timeout or cancellation - stop collecting responses
			return serviceMap
		}
	}
}

// processServiceEntry converts an mDNS entry to our service format and adds it to the map.
func processServiceEntry(entry *mdns.ServiceEntry, serviceQueries map[string]bool, serviceMap map[string]*common.MDNSService) {
	// Extract IP address from the entry
	var ip string
	if entry.AddrV4 != nil {
		ip = entry.AddrV4.String()
	} else if entry.AddrV6 != nil {
		ip = entry.AddrV6.String()
	}

	// Create unique key for deduplication
	uniqueServiceID := fmt.Sprintf("%s:%s:%d", entry.Name, ip, entry.Port)

	// Only add new services or update existing ones with missing IPs
	if existingService, exists := serviceMap[uniqueServiceID]; exists && existingService.IP != "" {
		return
	}

	// Parse TXT record data
	var txtData []string
	if entry.Info != "" {
		txtData = strings.Split(entry.Info, "\n")
	}

	// Match this entry to the original service query type
	matchedType := findMatchingServiceType(entry.Name, serviceQueries)

	service := &common.MDNSService{
		Name:    entry.Name,
		Type:    matchedType,
		IP:      ip,
		Port:    entry.Port,
		TXTData: txtData,
	}

	// Only store services with useful information
	if isValidService(service) {
		serviceMap[uniqueServiceID] = service
	}
}

// findMatchingServiceType matches a discovered service name to an original query.
func findMatchingServiceType(entryName string, serviceQueries map[string]bool) string {
	entryNameBase := strings.TrimSuffix(entryName, ".local")

	for originalService := range serviceQueries {
		serviceBase := strings.TrimSuffix(originalService, ".local")

		// Check for substring match in either direction
		if strings.Contains(entryNameBase, serviceBase) ||
			strings.Contains(serviceBase, entryNameBase) {
			return originalService
		}
	}

	return "_unknown._tcp.local"
}

// isValidService checks if a service has enough information to be useful.
// A service must have a name and either an IP address or port number.
func isValidService(service *common.MDNSService) bool {
	return service.Name != "" && (service.IP != "" || service.Port > 0)
}

// convertToServiceList transforms the service map to a list, resolving missing IPs.
func convertToServiceList(serviceMap map[string]*common.MDNSService) []common.MDNSService {
	services := make([]common.MDNSService, 0, len(serviceMap))

	for _, service := range serviceMap {
		// Attempt to resolve hostname if IP is missing or invalid
		if service.IP == "" || service.IP == "0.0.0.0" {
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

// parseMDNSPacket parses a DNS packet and extracts query information.
//
// DNS packet structure:
//
//	Header (12 bytes):
//	  - Transaction ID (2 bytes)
//	  - Flags (2 bytes) - includes QR bit to distinguish query/response
//	  - Question Count (2 bytes)
//	  - Answer Count (2 bytes)
//	  - Authority Count (2 bytes)
//	  - Additional Count (2 bytes)
//	Questions Section:
//	  - Variable length DNS names
//	  - QTYPE (2 bytes)
//	  - QCLASS (2 bytes)
//
// Returns nil if the packet is not a query or is malformed.
func parseMDNSPacket(data []byte, sourceIP string) *MDNSQuery {
	const dnsHeaderSize = 12

	// Validate minimum packet size
	if len(data) < dnsHeaderSize {
		return nil
	}

	// Parse DNS header flags (bytes 2-3)
	flags := binary.BigEndian.Uint16(data[2:4])

	// Check if this is a query (QR bit = 0) and not a response
	// QR bit is the most significant bit (0x8000) of the flags field
	const queryResponseBit = 0x8000
	isQuery := (flags & queryResponseBit) == 0
	if !isQuery {
		return nil
	}

	// Extract question count from header (bytes 4-5)
	questionCount := binary.BigEndian.Uint16(data[4:6])
	if questionCount == 0 {
		return nil
	}

	query := &MDNSQuery{
		SourceIP:  sourceIP,
		Timestamp: time.Now(),
		Questions: make([]string, 0, questionCount),
	}

	// Parse questions section starting after the header
	offset := dnsHeaderSize
	for i := uint16(0); i < questionCount && offset < len(data); i++ {
		serviceName, newOffset := parseDNSName(data, offset)
		if serviceName != "" {
			query.Questions = append(query.Questions, serviceName)
		}

		// Skip QTYPE (2 bytes) and QCLASS (2 bytes) to move to next question
		const qtypeAndQclassSize = 4
		offset = newOffset + qtypeAndQclassSize
		if offset > len(data) {
			break
		}
	}

	if len(query.Questions) > 0 {
		return query
	}
	return nil
}

// parseDNSName parses a DNS name from packet data, handling DNS compression.
//
// DNS names are encoded as length-prefixed labels:
//   - Each label starts with a length byte (0-63)
//   - Labels are dot-separated and terminated by a zero-length byte (0x00)
//   - Compression pointers (0xC0 prefix) can reference other positions in the packet
//
// Returns the parsed name and the offset after the name in the packet.
func parseDNSName(data []byte, offset int) (string, int) {
	const typicalLabelCount = 4
	dnsLabels := make([]string, 0, typicalLabelCount)

	hasJumped := false
	returnOffset := offset
	jumps := 0

	for jumps < maxDNSCompressionJumps && offset < len(data) {
		labelLength := int(data[offset])

		// Check for DNS compression pointer (top 2 bits are 11 = 0xC0)
		const compressionMask = 0xC0
		if labelLength&compressionMask == compressionMask {
			if offset+1 >= len(data) {
				break
			}

			// Extract pointer to another location in the packet
			// Mask off the compression bits (0x3FFF) to get the actual offset
			const pointerMask = 0x3FFF
			pointerOffset := int(binary.BigEndian.Uint16(data[offset:offset+2]) & pointerMask)

			// Save the position after the pointer for return
			if !hasJumped {
				returnOffset = offset + 2
			}

			offset = pointerOffset
			hasJumped = true
			jumps++
			continue
		}

		// End of name marker (zero-length label)
		if labelLength == 0 {
			offset++
			break
		}

		// Regular label: extract the label string
		if offset+1+labelLength > len(data) {
			break
		}
		label := string(data[offset+1 : offset+1+labelLength])
		dnsLabels = append(dnsLabels, label)
		offset += 1 + labelLength
	}

	// Return the appropriate offset based on whether we followed pointers
	if hasJumped {
		return strings.Join(dnsLabels, "."), returnOffset
	}
	return strings.Join(dnsLabels, "."), offset
}
