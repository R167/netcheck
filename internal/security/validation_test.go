package security

import (
	"net"
	"testing"
)

func TestValidateGatewayIP_ValidPrivateIPs(t *testing.T) {
	validIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.254",
		"169.254.1.1",
		"fc00::1",
		"fe80::1",
		"fd00::1",
	}

	for _, ip := range validIPs {
		err := ValidateGatewayIP(ip)
		if err != nil {
			t.Errorf("ValidateGatewayIP(%s) should be valid, got error: %v", ip, err)
		}
	}
}

func TestValidateGatewayIP_RejectPublicIPs(t *testing.T) {
	publicIPs := []string{
		"8.8.8.8",           // Google DNS
		"1.1.1.1",           // Cloudflare DNS
		"208.67.222.222",    // OpenDNS
		"2001:4860:4860::8888", // Google DNS IPv6
		"2606:4700:4700::1111", // Cloudflare DNS IPv6
	}

	for _, ip := range publicIPs {
		err := ValidateGatewayIP(ip)
		if err == nil {
			t.Errorf("ValidateGatewayIP(%s) should reject public IP", ip)
		}
	}
}

func TestValidateGatewayIP_RejectLoopback(t *testing.T) {
	loopbackIPs := []string{
		"127.0.0.1",
		"127.0.0.254",
		"::1",
	}

	for _, ip := range loopbackIPs {
		err := ValidateGatewayIP(ip)
		if err == nil {
			t.Errorf("ValidateGatewayIP(%s) should reject loopback address", ip)
		}
	}
}

func TestValidateGatewayIP_RejectMulticast(t *testing.T) {
	multicastIPs := []string{
		"224.0.0.1",
		"239.255.255.250",
		"ff02::1",
	}

	for _, ip := range multicastIPs {
		err := ValidateGatewayIP(ip)
		if err == nil {
			t.Errorf("ValidateGatewayIP(%s) should reject multicast address", ip)
		}
	}
}

func TestValidateGatewayIP_RejectInvalidFormat(t *testing.T) {
	invalidIPs := []string{
		"",
		"not-an-ip",
		"999.999.999.999",
		"192.168.1",
		"192.168.1.1.1",
		"gggg::1",
	}

	for _, ip := range invalidIPs {
		err := ValidateGatewayIP(ip)
		if err == nil {
			t.Errorf("ValidateGatewayIP(%s) should reject invalid format", ip)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"169.254.1.1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("Failed to parse test IP: %s", tt.ip)
		}

		result := IsPrivateIP(ip)
		if result != tt.isPrivate {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, result, tt.isPrivate)
		}
	}
}

func TestValidatePort(t *testing.T) {
	validPorts := []int{1, 80, 443, 8080, 65535}
	for _, port := range validPorts {
		err := ValidatePort(port)
		if err != nil {
			t.Errorf("ValidatePort(%d) should be valid, got error: %v", port, err)
		}
	}

	invalidPorts := []int{0, -1, 65536, 100000}
	for _, port := range invalidPorts {
		err := ValidatePort(port)
		if err == nil {
			t.Errorf("ValidatePort(%d) should be invalid", port)
		}
	}
}

func TestSanitizeHostname(t *testing.T) {
	validHostnames := []string{
		"example.com",
		"router.local",
		"gateway-1",
		"192.168.1.1",
		"my_router",
	}

	for _, hostname := range validHostnames {
		result, err := SanitizeHostname(hostname)
		if err != nil {
			t.Errorf("SanitizeHostname(%s) should be valid, got error: %v", hostname, err)
		}
		if result != hostname {
			t.Errorf("SanitizeHostname(%s) = %s, want %s", hostname, result, hostname)
		}
	}

	invalidHostnames := []string{
		"",
		"host;whoami",
		"host`whoami`",
		"host$(whoami)",
		"host|whoami",
		"host&whoami",
		"host\nwhoami",
	}

	for _, hostname := range invalidHostnames {
		_, err := SanitizeHostname(hostname)
		if err == nil {
			t.Errorf("SanitizeHostname(%s) should be invalid", hostname)
		}
	}
}
