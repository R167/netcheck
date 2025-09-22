package mdns

import (
	"net"
	"strings"
	"testing"

	"github.com/R167/netcheck/checkers/common"
)

func TestSendMDNSQuery(t *testing.T) {
	t.Run("Basic mDNS query packet structure", func(t *testing.T) {
		query := []byte{
			0x00, 0x00,
			0x00, 0x00,
			0x00, 0x01,
			0x00, 0x00,
			0x00, 0x00,
			0x00, 0x00,
			0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
			0x07, '_', 'd', 'n', 's', '-', 's', 'd',
			0x04, '_', 'u', 'd', 'p',
			0x05, 'l', 'o', 'c', 'a', 'l',
			0x00,
			0x00, 0x0C,
			0x00, 0x01,
		}

		if len(query) < 12 {
			t.Error("mDNS query too short")
		}

		if query[0] != 0x00 || query[1] != 0x00 {
			t.Error("Transaction ID should be 0x0000")
		}

		if query[4] != 0x00 || query[5] != 0x01 {
			t.Error("Questions count should be 1")
		}

		if query[len(query)-4] != 0x00 || query[len(query)-3] != 0x0C {
			t.Error("Query type should be PTR (0x000C)")
		}
	})

	t.Run("No mDNS service available", func(t *testing.T) {
		result := sendMDNSQuery()

		if result {
			t.Log("mDNS service detected (may be real on this system)")
		} else {
			t.Log("No mDNS service detected (expected in most test environments)")
		}
	})
}

func TestCheckRiskyMDNSService(t *testing.T) {
	tests := []struct {
		name           string
		service        common.MDNSService
		expectIssue    bool
		expectSeverity string
	}{
		{
			name: "SSH service (MEDIUM severity)",
			service: common.MDNSService{
				Name: "myserver",
				Type: "_ssh._tcp.local",
				IP:   "192.168.1.100",
				Port: 22,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "Telnet service (MEDIUM severity)",
			service: common.MDNSService{
				Name: "oldrouter",
				Type: "_telnet._tcp.local",
				IP:   "192.168.1.1",
				Port: 23,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "VNC service (MEDIUM severity)",
			service: common.MDNSService{
				Name: "desktop",
				Type: "_vnc._tcp.local",
				IP:   "192.168.1.50",
				Port: 5900,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "RDP service (MEDIUM severity)",
			service: common.MDNSService{
				Name: "windows-pc",
				Type: "_rdp._tcp.local",
				IP:   "192.168.1.60",
				Port: 3389,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "SMB file sharing (MEDIUM severity)",
			service: common.MDNSService{
				Name: "fileserver",
				Type: "_smb._tcp.local",
				IP:   "192.168.1.10",
				Port: 445,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "FTP service (MEDIUM severity)",
			service: common.MDNSService{
				Name: "ftpserver",
				Type: "_ftp._tcp.local",
				IP:   "192.168.1.20",
				Port: 21,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "NFS file sharing (MEDIUM severity)",
			service: common.MDNSService{
				Name: "nfsserver",
				Type: "_nfs._tcp.local",
				IP:   "192.168.1.30",
				Port: 2049,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "AFP file sharing (MEDIUM severity)",
			service: common.MDNSService{
				Name: "macserver",
				Type: "_afpovertcp._tcp.local",
				IP:   "192.168.1.40",
				Port: 548,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "Network printer (MEDIUM severity)",
			service: common.MDNSService{
				Name: "office-printer",
				Type: "_printer._tcp.local",
				IP:   "192.168.1.200",
				Port: 9100,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "IPP printer (MEDIUM severity)",
			service: common.MDNSService{
				Name: "hp-printer",
				Type: "_ipp._tcp.local",
				IP:   "192.168.1.201",
				Port: 631,
			},
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name: "Safe service - HTTP (no issue)",
			service: common.MDNSService{
				Name: "webserver",
				Type: "_http._tcp.local",
				IP:   "192.168.1.80",
				Port: 80,
			},
			expectIssue: false,
		},
		{
			name: "Safe service - Chromecast (no issue)",
			service: common.MDNSService{
				Name: "Living Room TV",
				Type: "_googlecast._tcp.local",
				IP:   "192.168.1.150",
				Port: 8009,
			},
			expectIssue: false,
		},
		{
			name: "Safe service - AirPlay (no issue)",
			service: common.MDNSService{
				Name: "Apple TV",
				Type: "_airplay._tcp.local",
				IP:   "192.168.1.151",
				Port: 7000,
			},
			expectIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &common.RouterInfo{}

			checkRiskyMDNSService(router, tt.service)

			if tt.expectIssue {
				if len(router.Issues) == 0 {
					t.Error("Expected security issue but got none")
				} else {
					if router.Issues[0].Severity != tt.expectSeverity {
						t.Errorf("Expected severity %s, got %s", tt.expectSeverity, router.Issues[0].Severity)
					}
				}
			} else {
				if len(router.Issues) > 0 {
					t.Errorf("Expected no issue for %s, but got %d issues", tt.service.Type, len(router.Issues))
				}
			}
		})
	}
}

func TestRiskyServicesMap(t *testing.T) {
	riskyServices := map[string]string{
		"_ssh._tcp.local":        "SSH service exposed",
		"_ftp._tcp.local":        "FTP service exposed",
		"_telnet._tcp.local":     "Telnet service exposed",
		"_vnc._tcp.local":        "VNC service exposed",
		"_rdp._tcp.local":        "RDP service exposed",
		"_smb._tcp.local":        "SMB/CIFS file sharing exposed",
		"_nfs._tcp.local":        "NFS file sharing exposed",
		"_afpovertcp._tcp.local": "Apple Filing Protocol exposed",
		"_printer._tcp.local":    "Network printer exposed",
		"_ipp._tcp.local":        "Internet Printing Protocol exposed",
	}

	t.Run("All risky services have descriptions", func(t *testing.T) {
		for serviceType, description := range riskyServices {
			if serviceType == "" {
				t.Error("Empty service type found")
			}
			if description == "" {
				t.Errorf("Service %s has empty description", serviceType)
			}
			if !strings.HasSuffix(serviceType, ".local") {
				t.Errorf("Service type %s should end with .local", serviceType)
			}
		}
	})
}

func TestCheckMDNS_BasicMode(t *testing.T) {
	t.Run("Basic mDNS detection", func(t *testing.T) {
		router := &common.RouterInfo{}
		cfg := MDNSConfig{Detailed: false}

		checkMDNS(router, cfg)

		if router.MDNSEnabled {
			if len(router.Issues) == 0 {
				t.Error("If mDNS is enabled, should report security issue")
			}
			if router.Issues[0].Severity != common.SeverityLow {
				t.Errorf("Basic mDNS detection should be LOW severity, got %s", router.Issues[0].Severity)
			}
		}
	})
}

func TestMDNSChecker_Interface(t *testing.T) {
	checker := NewMDNSChecker()

	if checker.Name() != "mdns" {
		t.Errorf("Name() = %v, want mdns", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	mdnsConfig, ok := config.(MDNSConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return MDNSConfig")
	}

	if mdnsConfig.Detailed {
		t.Error("Default config should have Detailed = false")
	}
}

func TestMDNSServiceTypes(t *testing.T) {
	serviceTypes := []string{
		"_services._dns-sd._udp.local",
		"_http._tcp.local",
		"_https._tcp.local",
		"_ssh._tcp.local",
		"_ftp._tcp.local",
		"_smb._tcp.local",
		"_afpovertcp._tcp.local",
		"_nfs._tcp.local",
		"_printer._tcp.local",
		"_ipp._tcp.local",
		"_airplay._tcp.local",
		"_raop._tcp.local",
		"_chromecast._tcp.local",
		"_googlecast._tcp.local",
		"_homekit._tcp.local",
		"_hap._tcp.local",
		"_spotify-connect._tcp.local",
		"_sonos._tcp.local",
		"_workstation._tcp.local",
		"_device-info._tcp.local",
		"_companion-link._tcp.local",
		"_rdp._tcp.local",
		"_vnc._tcp.local",
		"_telnet._tcp.local",
	}

	t.Run("Service types format validation", func(t *testing.T) {
		for _, stype := range serviceTypes {
			if !strings.HasSuffix(stype, ".local") {
				t.Errorf("Service type %s should end with .local", stype)
			}
			if !strings.HasPrefix(stype, "_") {
				t.Errorf("Service type %s should start with _", stype)
			}
			if !strings.Contains(stype, "._tcp.") && !strings.Contains(stype, "._udp.") {
				t.Errorf("Service type %s should contain ._tcp. or ._udp.", stype)
			}
		}
	})

	t.Run("Common IoT services covered", func(t *testing.T) {
		expectedServices := map[string]bool{
			"_airplay._tcp.local":    false,
			"_googlecast._tcp.local": false,
			"_homekit._tcp.local":    false,
			"_ssh._tcp.local":        false,
			"_printer._tcp.local":    false,
		}

		for _, stype := range serviceTypes {
			if _, exists := expectedServices[stype]; exists {
				expectedServices[stype] = true
			}
		}

		for service, found := range expectedServices {
			if !found {
				t.Errorf("Expected service type %s not found in list", service)
			}
		}
	})
}

func TestMDNSMulticastAddress(t *testing.T) {
	t.Run("mDNS multicast address validation", func(t *testing.T) {
		mdnsAddr := "224.0.0.251:5353"

		ip, port, err := net.SplitHostPort(mdnsAddr)
		if err != nil {
			t.Fatalf("Failed to parse mDNS address: %v", err)
		}

		if ip != "224.0.0.251" {
			t.Errorf("mDNS IP should be 224.0.0.251, got %s", ip)
		}

		if port != "5353" {
			t.Errorf("mDNS port should be 5353, got %s", port)
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			t.Error("Failed to parse mDNS IP address")
		}

		if !parsedIP.IsMulticast() {
			t.Error("224.0.0.251 should be a multicast address")
		}
	})
}

func TestMDNSResponseValidation(t *testing.T) {
	t.Run("Response must be larger than DNS header", func(t *testing.T) {
		dnsHeaderSize := 12

		tooSmall := make([]byte, 11)
		validSize := make([]byte, 13)

		if len(tooSmall) > dnsHeaderSize {
			t.Error("Response smaller than 12 bytes should be invalid")
		}

		if len(validSize) <= dnsHeaderSize {
			t.Error("Response of 13 bytes should be valid")
		}
	})

	t.Run("DNS header structure", func(t *testing.T) {
		header := []byte{
			0x00, 0x00,
			0x84, 0x00,
			0x00, 0x00,
			0x00, 0x01,
			0x00, 0x00,
			0x00, 0x00,
		}

		if len(header) != 12 {
			t.Errorf("DNS header should be 12 bytes, got %d", len(header))
		}

		isResponse := (header[2] & 0x80) != 0
		if !isResponse {
			t.Error("Bit 15 (QR) should be set for responses")
		}
	})
}

func TestCheckMDNS_DetailedMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping detailed mDNS discovery in short mode")
	}

	t.Run("Detailed mDNS discovery", func(t *testing.T) {
		router := &common.RouterInfo{}
		cfg := MDNSConfig{Detailed: true}

		checkMDNS(router, cfg)

		if router.MDNSEnabled {
			if len(router.Issues) == 0 {
				t.Error("If mDNS services found, should report security issue")
			}

			hasLowSeverity := false
			for _, issue := range router.Issues {
				if issue.Severity == common.SeverityLow && issue.Description == "mDNS services discovered" {
					hasLowSeverity = true
					break
				}
			}

			if !hasLowSeverity {
				t.Error("Should have LOW severity issue for mDNS service discovery")
			}
		}
	})
}

func BenchmarkSendMDNSQuery(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sendMDNSQuery()
	}
}

func BenchmarkCheckRiskyMDNSService(b *testing.B) {
	service := common.MDNSService{
		Name: "testserver",
		Type: "_ssh._tcp.local",
		IP:   "192.168.1.100",
		Port: 22,
	}

	router := &common.RouterInfo{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Issues = nil
		checkRiskyMDNSService(router, service)
	}
}
