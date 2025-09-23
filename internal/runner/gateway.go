package runner

import (
	"net"
	"strings"
)

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
