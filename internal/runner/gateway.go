package runner

import (
	"net"
	"strings"
)

// DiscoverGateway attempts to discover the network gateway IP address.
// It uses a UDP connection to a public IP (8.8.8.8) to determine the local
// interface, then assumes the gateway is .1 on the same subnet.
//
// Returns an empty string if gateway cannot be determined.
//
// Note: This is a heuristic and may not work on all network configurations.
// Future improvement: Parse actual routing table for more accurate results.
func DiscoverGateway() string {
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
