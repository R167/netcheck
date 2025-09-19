package cli

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type Config struct {
	All         bool
	Default     bool
	Web         bool
	Ports       bool
	UPnP        bool
	NATPmp      bool
	IPv6        bool
	MDNS        bool
	API         bool
	Starlink    bool
	Routes      bool
	Device      bool
	External    bool
	Proxy       bool
	LLDP        bool
	Timeout     time.Duration
	ShowVirtual bool
	PortTimeout time.Duration
}

func ParseFlags() *Config {
	cfg := &Config{}

	flag.BoolVar(&cfg.All, "all", false, "Run all available tests")
	flag.BoolVar(&cfg.Default, "default", false, "Run default test suite (same as no flags)")
	flag.BoolVar(&cfg.Web, "web", false, "Test web interface and default credentials")
	flag.BoolVar(&cfg.Ports, "ports", false, "Scan common management ports")
	flag.BoolVar(&cfg.UPnP, "upnp", false, "Test UPnP services and port mappings")
	flag.BoolVar(&cfg.NATPmp, "natpmp", false, "Test NAT-PMP services")
	flag.BoolVar(&cfg.IPv6, "ipv6", false, "Check IPv6 configuration")
	flag.BoolVar(&cfg.MDNS, "mdns", false, "Perform comprehensive mDNS service discovery")
	flag.BoolVar(&cfg.API, "api", false, "Check for exposed router APIs")
	flag.BoolVar(&cfg.Starlink, "starlink", false, "Check for Starlink Dishy")
	flag.BoolVar(&cfg.Routes, "routes", false, "Display routing information")
	flag.BoolVar(&cfg.Device, "device", false, "Display interface/device information")
	flag.BoolVar(&cfg.External, "external", false, "Discover external IPv4/IPv6 addresses")
	flag.BoolVar(&cfg.Proxy, "proxy", false, "Test proxy configuration (requires --external)")
	flag.BoolVar(&cfg.LLDP, "lldp", false, "Link layer discovery and debugging")
	flag.DurationVar(&cfg.Timeout, "timeout", 60*time.Second, "Maximum time to run all tests (e.g. 30s, 2m, 1h)")
	flag.BoolVar(&cfg.ShowVirtual, "show-virtual", false, "Show virtual network interfaces (VPN tunnels, Docker bridges, etc.)")
	flag.DurationVar(&cfg.PortTimeout, "port-timeout", time.Second, "Timeout for individual port scans (e.g. 500ms, 1s, 2s)")

	return cfg
}

func Run(cfg *Config) error {
	fmt.Println("🔍 Network Gateway Security Checker")
	fmt.Println("====================================")

	fmt.Println("CLI mode running with selected checks")
	return nil
}

func ShowUsage() {
	fmt.Fprintf(os.Stderr, "Usage: netcheck [options]\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}
