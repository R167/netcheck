package ports

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/R167/netcheck/checkers/common"
)

func TestIsPortOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	tests := []struct {
		name    string
		ip      string
		port    int
		timeout time.Duration
		want    bool
	}{
		{
			name:    "Open port",
			ip:      "127.0.0.1",
			port:    port,
			timeout: 1 * time.Second,
			want:    true,
		},
		{
			name:    "Closed port",
			ip:      "127.0.0.1",
			port:    port + 1,
			timeout: 1 * time.Second,
			want:    false,
		},
		{
			name:    "Invalid IP",
			ip:      "999.999.999.999",
			port:    80,
			timeout: 1 * time.Second,
			want:    false,
		},
		{
			name:    "Unreachable IP with short timeout",
			ip:      "192.0.2.1", // TEST-NET-1 (should be unreachable)
			port:    80,
			timeout: 100 * time.Millisecond,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPortOpen(tt.ip, tt.port, tt.timeout)
			if got != tt.want {
				t.Errorf("isPortOpen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanCommonPorts(t *testing.T) {
	listeners := make([]net.Listener, 3)
	openPorts := make([]int, 3)

	for i := 0; i < 3; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener %d: %v", i, err)
		}
		defer listener.Close()
		listeners[i] = listener

		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		openPorts[i], _ = strconv.Atoi(portStr)
	}

	tests := []struct {
		name          string
		scanPorts     []int
		expectedCount int
	}{
		{
			name:          "Scan with open ports",
			scanPorts:     openPorts,
			expectedCount: 3,
		},
		{
			name:          "Scan with closed ports",
			scanPorts:     []int{65530, 65531, 65532},
			expectedCount: 0,
		},
		{
			name:          "Mixed open and closed",
			scanPorts:     []int{openPorts[0], 65530, openPorts[1]},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &common.RouterInfo{
				IP: "127.0.0.1",
			}

			cfg := PortsConfig{
				Ports:       tt.scanPorts,
				PortTimeout: 500 * time.Millisecond,
			}

			scanCommonPorts(router, cfg)

			if len(router.OpenPorts) != tt.expectedCount {
				t.Errorf("Found %d open ports, want %d", len(router.OpenPorts), tt.expectedCount)
			}
		})
	}
}

func TestManagementPortSecurityIssues(t *testing.T) {
	tests := []struct {
		name           string
		port           int
		expectIssue    bool
		expectSeverity string
	}{
		{
			name:           "SSH port 22",
			port:           22,
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name:           "Telnet port 23",
			port:           23,
			expectIssue:    true,
			expectSeverity: common.SeverityHigh,
		},
		{
			name:           "SNMP port 161",
			port:           161,
			expectIssue:    true,
			expectSeverity: common.SeverityMedium,
		},
		{
			name:        "HTTP port 80 (no specific issue)",
			port:        80,
			expectIssue: false,
		},
		{
			name:        "HTTPS port 443 (no specific issue)",
			port:        443,
			expectIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to create listener: %v", err)
			}
			defer listener.Close()

			_, portStr, _ := net.SplitHostPort(listener.Addr().String())
			actualPort, _ := strconv.Atoi(portStr)

			router := &common.RouterInfo{
				IP: "127.0.0.1",
			}

			if tt.port == 22 {
				actualPort = 22
				listener.Close()
				var err error
				listener, err = net.Listen("tcp", "127.0.0.1:22")
				if err != nil {
					t.Skipf("Cannot bind to port 22: %v", err)
				}
				defer listener.Close()
			} else if tt.port == 23 || tt.port == 161 {
				t.Skip("Skipping privileged port test")
			}

			cfg := PortsConfig{
				Ports:       []int{actualPort},
				PortTimeout: 500 * time.Millisecond,
			}

			scanCommonPorts(router, cfg)

			if tt.expectIssue {
				if actualPort == tt.port {
					if len(router.Issues) == 0 {
						t.Error("Expected security issue but got none")
					} else if router.Issues[0].Severity != tt.expectSeverity {
						t.Errorf("Expected severity %s, got %s", tt.expectSeverity, router.Issues[0].Severity)
					}
				}
			} else {
				if len(router.Issues) > 0 {
					t.Errorf("Expected no issues for port %d, but got %d issues", tt.port, len(router.Issues))
				}
			}
		})
	}
}

func TestManagementPortsMap(t *testing.T) {
	t.Run("All documented ports have issues defined", func(t *testing.T) {
		expectedPorts := []int{22, 23, 161}

		for _, port := range expectedPorts {
			issue, exists := managementPorts[port]
			if !exists {
				t.Errorf("Port %d missing from managementPorts", port)
			}
			if issue.Severity == "" {
				t.Errorf("Port %d has no severity defined", port)
			}
			if issue.Description == "" {
				t.Errorf("Port %d has no description", port)
			}
			if issue.Details == "" {
				t.Errorf("Port %d has no details", port)
			}
		}
	})

	t.Run("SSH has correct severity", func(t *testing.T) {
		issue := managementPorts[22]
		if issue.Severity != common.SeverityMedium {
			t.Errorf("SSH severity = %s, want MEDIUM", issue.Severity)
		}
	})

	t.Run("Telnet has high severity", func(t *testing.T) {
		issue := managementPorts[23]
		if issue.Severity != common.SeverityHigh {
			t.Errorf("Telnet severity = %s, want HIGH", issue.Severity)
		}
	})
}

func TestPortsChecker_Interface(t *testing.T) {
	checker := NewPortsChecker()

	if checker.Name() != "ports" {
		t.Errorf("Name() = %v, want ports", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	portsConfig, ok := config.(PortsConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return PortsConfig")
	}

	if len(portsConfig.Ports) == 0 {
		t.Error("Default config should include ports to scan")
	}

	expectedPorts := map[int]bool{
		22:   true,
		23:   true,
		80:   true,
		443:  true,
		8080: true,
	}

	for port := range expectedPorts {
		found := false
		for _, p := range portsConfig.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Port %d not in default port list", port)
		}
	}

	if portsConfig.PortTimeout != common.PortTimeout {
		t.Errorf("PortTimeout = %v, want %v", portsConfig.PortTimeout, common.PortTimeout)
	}
}

func TestPortScanTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	t.Run("Port scan respects timeout", func(t *testing.T) {
		start := time.Now()
		isPortOpen("192.0.2.1", 80, 100*time.Millisecond)
		elapsed := time.Since(start)

		if elapsed > 500*time.Millisecond {
			t.Errorf("Port scan took %v, should respect 100ms timeout", elapsed)
		}
	})
}

func TestEmptyPortList(t *testing.T) {
	router := &common.RouterInfo{
		IP: "127.0.0.1",
	}

	cfg := PortsConfig{
		Ports:       []int{},
		PortTimeout: 1 * time.Second,
	}

	scanCommonPorts(router, cfg)

	if len(router.OpenPorts) != 0 {
		t.Errorf("Expected no ports to be scanned, got %d", len(router.OpenPorts))
	}
}

func TestMultipleOpenPorts(t *testing.T) {
	listeners := make([]net.Listener, 5)
	ports := make([]int, 5)

	for i := 0; i < 5; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer listener.Close()
		listeners[i] = listener

		_, portStr, _ := net.SplitHostPort(listener.Addr().String())
		ports[i], _ = strconv.Atoi(portStr)
	}

	router := &common.RouterInfo{
		IP: "127.0.0.1",
	}

	cfg := PortsConfig{
		Ports:       ports,
		PortTimeout: 500 * time.Millisecond,
	}

	scanCommonPorts(router, cfg)

	if len(router.OpenPorts) != 5 {
		t.Errorf("Expected 5 open ports, got %d", len(router.OpenPorts))
	}

	for i, port := range ports {
		if router.OpenPorts[i] != port {
			t.Errorf("Port %d: got %d, want %d", i, router.OpenPorts[i], port)
		}
	}
}

func BenchmarkIsPortOpen(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isPortOpen("127.0.0.1", port, 1*time.Second)
	}
}

func BenchmarkScanCommonPorts(b *testing.B) {
	router := &common.RouterInfo{
		IP: "127.0.0.1",
	}

	cfg := PortsConfig{
		Ports:       []int{65530, 65531, 65532, 65533, 65534},
		PortTimeout: 100 * time.Millisecond,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.OpenPorts = nil
		scanCommonPorts(router, cfg)
	}
}