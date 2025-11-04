package mdns_listen

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type MDNSListenChecker struct{}

type MDNSListenConfig struct {
	Timeout time.Duration
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

	for sourceIP, query := range queries {
		out.Info("")
		out.Info("Source: %s", sourceIP)

		// Deduplicate questions
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
