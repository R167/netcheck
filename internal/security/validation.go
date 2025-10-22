package security

import (
	"fmt"
	"net"
)

// ValidateGatewayIP validates that an IP address is suitable for use as a gateway target.
// It ensures the IP is:
// 1. A valid IP address format
// 2. Within private IP ranges (RFC 1918 for IPv4, RFC 4193 for IPv6)
// 3. Not a loopback address
// 4. Not a multicast address
//
// This validation prevents the tool from being misused to scan external networks
// or public IP addresses, limiting it to local network security assessments only.
func ValidateGatewayIP(ipStr string) error {
	if ipStr == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address format: %s", ipStr)
	}

	// Reject loopback addresses
	if ip.IsLoopback() {
		return fmt.Errorf("loopback addresses not allowed: %s", ipStr)
	}

	// Reject multicast addresses
	if ip.IsMulticast() {
		return fmt.Errorf("multicast addresses not allowed: %s", ipStr)
	}

	// Reject unspecified addresses (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified addresses not allowed: %s", ipStr)
	}

	// Only allow private IP ranges
	if !isPrivateIP(ip) {
		return fmt.Errorf("only private IP addresses allowed (RFC 1918/4193): %s", ipStr)
	}

	return nil
}

// isPrivateIP checks if an IP address is within private/local ranges
func isPrivateIP(ip net.IP) bool {
	// RFC 1918 private IPv4 ranges and RFC 4193 IPv6 ULA
	privateRanges := []string{
		"10.0.0.0/8",       // RFC 1918 - Private IPv4
		"172.16.0.0/12",    // RFC 1918 - Private IPv4
		"192.168.0.0/16",   // RFC 1918 - Private IPv4
		"fc00::/7",         // RFC 4193 - IPv6 Unique Local Addresses
		"fe80::/10",        // RFC 4291 - IPv6 Link-Local
		"169.254.0.0/16",   // RFC 3927 - IPv4 Link-Local
		"fd00::/8",         // IPv6 ULA (subset of fc00::/7)
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDR (shouldn't happen with hardcoded values)
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPrivateIP is exported for use in other packages
func IsPrivateIP(ip net.IP) bool {
	return isPrivateIP(ip)
}

// ValidatePort validates that a port number is within valid range
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", port)
	}
	return nil
}

// SanitizeHostname removes potentially dangerous characters from hostnames
// This prevents any potential injection attacks if hostname is used in commands
func SanitizeHostname(hostname string) (string, error) {
	if hostname == "" {
		return "", fmt.Errorf("hostname cannot be empty")
	}

	// Basic hostname validation - alphanumeric, dots, hyphens only
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-' || char == '_') {
			return "", fmt.Errorf("invalid character in hostname: %c", char)
		}
	}

	if len(hostname) > 253 {
		return "", fmt.Errorf("hostname too long: %d characters (max 253)", len(hostname))
	}

	return hostname, nil
}
