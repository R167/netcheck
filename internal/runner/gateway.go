package runner

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// DiscoverGateway attempts to discover the network gateway IP address.
//
// It first tries to parse the Linux routing table (/proc/net/route) for the
// default route (destination 00000000). If that fails, it falls back to a
// heuristic using a UDP socket.
func DiscoverGateway() string {
	if gw := discoverFromProcRoute(); gw != "" {
		return gw
	}
	return discoverFromUDP()
}

// discoverFromProcRoute parses /proc/net/route to find the default gateway.
// The gateway field is a little-endian hex-encoded IPv4 address.
func discoverFromProcRoute() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Default route has destination 00000000
		if fields[1] != "00000000" {
			continue
		}
		gateway := fields[2]
		if gateway == "00000000" {
			continue
		}
		return parseHexIP(gateway)
	}
	if err := scanner.Err(); err != nil {
		return ""
	}
	return ""
}

// parseHexIP converts a hex-encoded IPv4 address from /proc/net/route to dotted notation.
// The kernel stores these in host byte order, which is little-endian on x86.
func parseHexIP(hexAddr string) string {
	b, err := hex.DecodeString(hexAddr)
	if err != nil || len(b) != 4 {
		return ""
	}
	// Reverse for little-endian host byte order
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

// discoverFromUDP uses a UDP socket to determine the local IP and assumes
// the gateway is .1 on the same subnet. This is a fallback heuristic.
func discoverFromUDP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}

	parts[3] = "1"
	return strings.Join(parts, ".")
}
