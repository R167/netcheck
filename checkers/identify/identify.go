package identify

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
	"github.com/endobit/oui"
)

type IdentifyChecker struct{}

type IdentifyConfig struct {
	// Ports to probe for banners/fingerprints. If empty, a default set is scanned.
	Ports []int
	// PortTimeout is the connection timeout for port probes.
	PortTimeout time.Duration
	// UseNmap enables nmap-based scanning when nmap is available on the host.
	UseNmap bool
	// NmapArgs allows passing additional nmap flags (e.g. "--top-ports 100").
	NmapArgs string
}

func NewIdentifyChecker() checker.Checker {
	return &IdentifyChecker{}
}

func (c *IdentifyChecker) Name() string { return "identify" }
func (c *IdentifyChecker) Description() string {
	return "Identify remote hosts via ARP, MAC OUI, nmap service detection, HTTP fingerprinting, and TCP banners"
}
func (c *IdentifyChecker) Icon() string         { return "🔎" }
func (c *IdentifyChecker) RequiresRouter() bool { return true }
func (c *IdentifyChecker) DefaultEnabled() bool { return false }

func (c *IdentifyChecker) DefaultConfig() checker.CheckerConfig {
	return IdentifyConfig{
		Ports:       []int{22, 80, 443, 554, 3000, 5000, 5001, 8080, 8443, 8123, 9090, 9100, 32400},
		PortTimeout: 2 * time.Second,
		UseNmap:     true,
	}
}

func (c *IdentifyChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyGateway, checker.DependencyRouterInfo, checker.DependencyNetwork}
}

func (c *IdentifyChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	cfg, ok := config.(IdentifyConfig)
	if !ok {
		cfg = c.DefaultConfig().(IdentifyConfig)
	}
	identifyHost(router, cfg, out)
}

func (c *IdentifyChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {}

func (c *IdentifyChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "identify_host",
		Description: "Identify a network host: resolve MAC address via ARP, look up hardware vendor (OUI), use nmap for service version detection, grab HTTP headers, and read TCP service banners to fingerprint the device",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the host to identify",
				},
				"ports": map[string]interface{}{
					"type":        "array",
					"description": "Ports to probe for service banners (default: common service ports)",
					"items":       map[string]interface{}{"type": "integer"},
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

// nmapAvailable checks if nmap is installed on the host.
func nmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// nmapResult holds a parsed nmap port/service result.
type nmapResult struct {
	Port     int
	State    string
	Service  string
	Version  string
	Protocol string
}

// runNmapVersionScan runs nmap -sV only against known-open ports for fast targeted
// version detection. Uses --version-intensity 0 for speed (only most likely probes).
func runNmapVersionScan(ip string, openPorts []int, extraArgs string) ([]nmapResult, string, error) {
	if len(openPorts) == 0 {
		return nil, "", nil
	}

	portStrs := make([]string, len(openPorts))
	for i, p := range openPorts {
		portStrs[i] = strconv.Itoa(p)
	}

	args := []string{
		"-sV",                      // Version detection
		"--version-intensity", "2", // Low intensity for speed (default is 7)
		"-Pn",                   // Skip host discovery (we know it's up)
		"-T4",                   // Aggressive timing
		"--host-timeout", "20s", // Cap total time
		"-p", strings.Join(portStrs, ","),
	}

	if extraArgs != "" {
		args = append(args, strings.Fields(extraArgs)...)
	}

	args = append(args, ip)

	cmd := exec.Command("nmap", args...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return nil, string(data), err
	}

	raw := string(data)
	results := parseNmapOutput(raw)
	return results, raw, nil
}

// parseNmapOutput parses standard nmap text output for port/service lines.
func parseNmapOutput(raw string) []nmapResult {
	var results []nmapResult
	// Match lines like: "22/tcp   open  ssh     OpenSSH 9.2p1 Debian-2+deb12u7"
	portLineRe := regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)$`)

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		match := portLineRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		port, _ := strconv.Atoi(match[1])
		results = append(results, nmapResult{
			Port:     port,
			Protocol: match[2],
			State:    match[3],
			Service:  match[4],
			Version:  strings.TrimSpace(match[5]),
		})
	}
	return results
}

// identifyHost runs all identification techniques against the target IP.
// Strategy: fast Go TCP connect to find open ports, then targeted nmap -sV
// only on those ports for version detection (avoids slow full nmap scans).
func identifyHost(router *common.RouterInfo, cfg IdentifyConfig, out output.Output) {
	ip := router.IP
	out.Section("🔎", fmt.Sprintf("Identifying host %s...", ip))

	// Step 1: ARP lookup + OUI vendor
	mac := lookupARP(ip)
	if mac == "" {
		out.Info("MAC address not found in ARP table, populating ARP cache...")
		populateARP(ip)
		mac = lookupARP(ip)
	}
	if mac != "" {
		out.Success("MAC address: %s", mac)
		if vendor := oui.Vendor(mac); vendor != "" {
			out.Success("Hardware vendor: %s", vendor)
		} else {
			firstOctet, err := strconv.ParseUint(mac[:2], 16, 8)
			if err == nil && firstOctet&0x02 != 0 {
				out.Info("MAC is locally-administered (randomized/private Wi-Fi address)")
			} else {
				out.Info("Hardware vendor: unknown (OUI prefix %s not in database)", mac[:8])
			}
		}
	} else {
		out.Warning("Could not resolve MAC address for %s", ip)
	}

	// Step 2: Reverse DNS lookup
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		out.Success("Reverse DNS: %s", strings.Join(names, ", "))
	}

	// Step 3: Fast Go TCP connect scan to find open ports
	out.Section("🔍", "Scanning ports...")
	openPorts := fastPortScan(ip, cfg.Ports, cfg.PortTimeout)
	if len(openPorts) == 0 {
		out.Info("No open ports found in scan set")
		return
	}
	out.Success("Open ports: %v", openPorts)
	router.OpenPorts = openPorts

	// Step 4: Targeted nmap version detection on open ports only (if available)
	nmapRan := false
	if cfg.UseNmap && nmapAvailable() {
		out.Section("🔬", fmt.Sprintf("Running nmap version detection on %d open port(s)...", len(openPorts)))
		results, raw, err := runNmapVersionScan(ip, openPorts, cfg.NmapArgs)
		if err != nil {
			out.Warning("nmap failed, falling back to banner grab: %v", err)
		} else {
			nmapRan = true
			for _, r := range results {
				version := r.Version
				if version == "" {
					version = r.Service
				} else {
					version = fmt.Sprintf("%s — %s", r.Service, version)
				}
				out.Success("Port %d/%s: %s", r.Port, r.Protocol, version)
			}
			extractNmapHostInfo(raw, out)
		}
	}

	// Step 5: Manual banner grab as fallback (only if nmap didn't run)
	if !nmapRan {
		out.Section("🌐", "Grabbing service banners...")
		for _, port := range openPorts {
			fingerprint := fingerprintPort(ip, port, cfg.PortTimeout)
			if fingerprint != "" {
				out.Detail("Port %d: %s", port, fingerprint)
			}
		}
	}

	// Step 6: HTTP fingerprinting on likely HTTP ports
	httpPorts := filterHTTPPorts(openPorts)
	for _, port := range httpPorts {
		out.Section("📄", fmt.Sprintf("HTTP fingerprint (port %d)...", port))
		httpFingerprint(ip, port, out)
	}
}

// fastPortScan does concurrent TCP connect scans and returns open ports.
func fastPortScan(ip string, ports []int, timeout time.Duration) []int {
	type result struct {
		port int
		open bool
	}
	ch := make(chan result, len(ports))

	for _, port := range ports {
		go func(p int) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), timeout)
			if err != nil {
				ch <- result{p, false}
				return
			}
			conn.Close()
			ch <- result{p, true}
		}(port)
	}

	var open []int
	for range ports {
		r := <-ch
		if r.open {
			open = append(open, r.port)
		}
	}

	// Sort to keep consistent order
	sortPorts(open)
	return open
}

// sortPorts sorts a slice of ints in ascending order (simple insertion sort for small slices).
func sortPorts(ports []int) {
	for i := 1; i < len(ports); i++ {
		key := ports[i]
		j := i - 1
		for j >= 0 && ports[j] > key {
			ports[j+1] = ports[j]
			j--
		}
		ports[j+1] = key
	}
}

// extractNmapHostInfo looks for extra nmap output lines like "Service Info", MAC, etc.
func extractNmapHostInfo(raw string, out output.Output) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Service Info:") {
			out.Detail("%s", line)
		}
		if strings.HasPrefix(line, "MAC Address:") {
			out.Detail("%s", line)
		}
	}
}

// lookupARP reads the system ARP table to find a MAC for the given IP.
func lookupARP(ip string) string {
	// Try Linux /proc/net/arp first
	mac := lookupARPProc(ip)
	if mac != "" {
		return mac
	}
	// Fall back to arp command
	return lookupARPCommand(ip)
}

// lookupARPProc reads /proc/net/arp (Linux).
func lookupARPProc(ip string) string {
	cmd := exec.Command("cat", "/proc/net/arp")
	data, err := cmd.Output()
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return strings.ToUpper(mac)
			}
		}
	}
	return ""
}

// lookupARPCommand uses the arp command (cross-platform fallback).
func lookupARPCommand(ip string) string {
	cmd := exec.Command("arp", "-n", ip)
	data, err := cmd.Output()
	if err != nil {
		// Try without -n flag (macOS)
		cmd = exec.Command("arp", ip)
		data, err = cmd.Output()
		if err != nil {
			return ""
		}
	}
	// Parse arp output for MAC address pattern
	macRe := regexp.MustCompile(`([0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2})`)
	match := macRe.FindString(string(data))
	if match != "" {
		return strings.ToUpper(normalizeMAC(match))
	}
	return ""
}

// normalizeMAC ensures MAC address octets are zero-padded.
func normalizeMAC(mac string) string {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// populateARP sends a ping to force an ARP entry.
func populateARP(ip string) {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	_ = cmd.Run()
}

// fingerprintPort attempts to read a TCP banner from a port.
func fingerprintPort(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// For known non-banner ports, just report the common service name
	switch port {
	case 80, 8080:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 554:
		return "RTSP (video streaming)"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8123:
		return "Home Assistant"
	case 9090:
		return "Prometheus"
	case 9100:
		return "Node Exporter / Printer (RAW)"
	case 32400:
		return "Plex Media Server"
	}

	// Try to read a banner for ports that typically send one (SSH, FTP, SMTP, etc.)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "open (no banner)"
	}
	banner := strings.TrimSpace(string(buf[:n]))
	// Sanitize: only keep first line, limit length
	if idx := strings.IndexAny(banner, "\r\n"); idx >= 0 {
		banner = banner[:idx]
	}
	if len(banner) > 120 {
		banner = banner[:120] + "..."
	}
	return banner
}

// filterHTTPPorts returns ports likely to serve HTTP/HTTPS.
func filterHTTPPorts(ports []int) []int {
	httpSet := map[int]bool{80: true, 443: true, 3000: true, 5000: true, 5001: true, 8080: true, 8443: true, 8123: true, 8888: true, 9090: true, 32400: true}
	var result []int
	for _, p := range ports {
		if httpSet[p] {
			result = append(result, p)
		}
	}
	return result
}

// httpFingerprint fetches HTTP headers and page title from a target.
func httpFingerprint(ip string, port int, out output.Output) {
	scheme := "http"
	if port == 443 || port == 8443 || port == 5001 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		out.Detail("  Could not connect: %v", err)
		return
	}
	defer resp.Body.Close()

	// Report status and server header
	out.Detail("  Status: %s", resp.Status)
	if server := resp.Header.Get("Server"); server != "" {
		out.Detail("  Server: %s", server)
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		out.Detail("  X-Powered-By: %s", powered)
	}
	if generator := resp.Header.Get("X-Generator"); generator != "" {
		out.Detail("  X-Generator: %s", generator)
	}
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		out.Detail("  WWW-Authenticate: %s", wwwAuth)
	}

	// Read body for title extraction
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	// Extract <title>
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if match := titleRe.FindSubmatch(body); len(match) >= 2 {
		title := strings.TrimSpace(string(match[1]))
		if title != "" {
			out.Detail("  Title: %s", title)
		}
	}

	// Look for common framework identifiers in the body
	detectFrameworks(string(body), out)
}

// detectFrameworks checks the HTTP body for known application signatures.
func detectFrameworks(body string, out output.Output) {
	frameworks := []struct {
		name     string
		patterns []string
	}{
		{"Synology DSM", []string{"Synology"}},
		{"Home Assistant", []string{"Home Assistant", "homeassistant"}},
		{"Ubiquiti UniFi", []string{"UniFi", "ubnt"}},
		{"Plex", []string{"Plex"}},
		{"Grafana", []string{"Grafana"}},
		{"Pi-hole", []string{"Pi-hole", "pihole"}},
		{"AdGuard Home", []string{"AdGuard"}},
		{"Portainer", []string{"Portainer"}},
		{"Proxmox", []string{"Proxmox"}},
		{"TrueNAS/FreeNAS", []string{"TrueNAS", "FreeNAS"}},
		{"Nextcloud", []string{"Nextcloud"}},
		{"Jellyfin", []string{"Jellyfin"}},
		{"Emby", []string{"Emby"}},
		{"OPNsense", []string{"OPNsense"}},
		{"pfSense", []string{"pfSense"}},
		{"OpenWrt", []string{"OpenWrt", "LuCI"}},
		{"Cockpit", []string{"cockpit-ws"}},
		{"Traefik", []string{"Traefik"}},
	}

	for _, fw := range frameworks {
		for _, pattern := range fw.patterns {
			if strings.Contains(body, pattern) {
				out.Detail("  Framework: %s detected", fw.name)
				break
			}
		}
	}
}
