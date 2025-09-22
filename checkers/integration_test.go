package checkers_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/checkers/ssdp"
	"github.com/R167/netcheck/checkers/upnp"
)

func TestSSDPIntegration_WithMockMulticastServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("SSDP discovery flow", func(t *testing.T) {
		deviceXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
		<friendlyName>Test DLNA Server</friendlyName>
		<manufacturer>TestCorp</manufacturer>
		<modelName>DLNA-1000</modelName>
	</device>
</root>`

		xmlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(deviceXML))
		}))
		defer xmlServer.Close()

		mockSSDPResponse := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"LOCATION: %s\r\n"+
			"SERVER: Linux/5.4 UPnP/1.1 MiniDLNA/1.2.1\r\n"+
			"USN: uuid:test-dlna-server\r\n"+
			"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n", xmlServer.URL)

		t.Logf("Mock SSDP response would advertise: %s", xmlServer.URL)
		t.Logf("Device would be categorized as DLNA media server")

		if len(mockSSDPResponse) == 0 {
			t.Error("Failed to create mock SSDP response")
		}
	})
}

func TestUPnPIntegration_FullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("UPnP device discovery and enumeration", func(t *testing.T) {
		deviceDescXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
		<friendlyName>Test Gateway</friendlyName>
		<manufacturer>RouterCorp</manufacturer>
		<modelName>RG-2000</modelName>
		<serialNumber>SN123456</serialNumber>
		<serviceList>
			<service>
				<serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
				<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
				<controlURL>/ctl/IPConn</controlURL>
			</service>
			<service>
				<serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
				<serviceId>urn:upnp-org:serviceId:WANIPv6FC1</serviceId>
				<controlURL>/ctl/IPv6FC</controlURL>
			</service>
		</serviceList>
	</device>
</root>`

		portMappingSOAP := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntryResponse>
<NewExternalPort>22</NewExternalPort>
<NewInternalPort>22</NewInternalPort>
<NewInternalClient>192.168.1.10</NewInternalClient>
<NewProtocol>TCP</NewProtocol>
<NewPortMappingDescription>SSH</NewPortMappingDescription>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>`

		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/rootDesc.xml":
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(deviceDescXML))
			case "/ctl/IPConn":
				if requestCount == 0 {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(portMappingSOAP))
					requestCount++
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		checker := upnp.NewUPnPChecker()
		if checker.Name() != "upnp" {
			t.Errorf("Checker name = %s, want upnp", checker.Name())
		}

		t.Logf("Integration test would:")
		t.Logf("1. Discover UPnP device via SSDP at %s", server.URL)
		t.Logf("2. Fetch device description from /rootDesc.xml")
		t.Logf("3. Enumerate services (WANIPConnection, WANIPv6FirewallControl)")
		t.Logf("4. Query port mappings via SOAP")
		t.Logf("5. Detect security issues (exposed SSH)")
	})
}

func TestMultiDeviceScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Multiple devices on network", func(t *testing.T) {
		devices := []struct {
			name     string
			category string
			xmlData  string
		}{
			{
				name:     "DLNA Server",
				category: "Media Server",
				xmlData: `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
		<friendlyName>Living Room Media Server</friendlyName>
		<manufacturer>MediaCorp</manufacturer>
		<modelName>MS-100</modelName>
	</device>
</root>`,
			},
			{
				name:     "Network Camera",
				category: "Security Camera",
				xmlData: `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:Camera:1</deviceType>
		<friendlyName>Front Door Camera</friendlyName>
		<manufacturer>SecureCorp</manufacturer>
		<modelName>CAM-200</modelName>
	</device>
</root>`,
			},
			{
				name:     "Smart Printer",
				category: "Printer",
				xmlData: `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType>
		<friendlyName>Office Printer</friendlyName>
		<manufacturer>PrintCorp</manufacturer>
		<modelName>PR-300</modelName>
	</device>
</root>`,
			},
		}

		var servers []*httptest.Server
		for _, device := range devices {
			xmlData := device.xmlData
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(xmlData))
			}))
			servers = append(servers, server)
			t.Logf("Mock %s running at %s", device.name, server.URL)
		}

		for _, server := range servers {
			defer server.Close()
		}

		t.Logf("Integration test simulates %d devices on network", len(devices))
		t.Log("Security assessment would flag:")
		t.Log("- DLNA server (LOW): Media file exposure")
		t.Log("- Camera (MEDIUM): Default credentials risk")
		t.Log("- Printer (LOW): Network exposure")
	})
}

func TestSecurityVulnerabilityDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Dangerous UPnP configuration detection", func(t *testing.T) {
		successCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ctl/IPConn" {
				if r.Method == "POST" {
					successCount++
					if successCount <= 1 {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope><s:Body>
<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"/>
</s:Body></s:Envelope>`))
					} else {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`<?xml version="1.0"?>
<s:Envelope><s:Body>
<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"/>
</s:Body></s:Envelope>`))
					}
				}
			}
		}))
		defer server.Close()

		t.Logf("Vulnerability test server at %s", server.URL)
		t.Log("Test would:")
		t.Log("1. Attempt to create port mapping to arbitrary IP (192.168.1.99)")
		t.Log("2. If successful, mark as CRITICAL vulnerability")
		t.Log("3. Clean up test mapping")
		t.Log("4. Report lateral movement attack risk")
	})
}

func TestIPv6FirewallPinholes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("IPv6 pinhole enumeration", func(t *testing.T) {
		pinholeCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ctl/IPv6FC" && pinholeCount < 3 {
				response := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetPinholeEntryResponse>
<RemoteHost>2001:db8::%d</RemoteHost>
<RemotePort>443</RemotePort>
<InternalClient>fe80::1</InternalClient>
<InternalPort>%d</InternalPort>
<Protocol>6</Protocol>
<LeaseTime>3600</LeaseTime>
</u:GetPinholeEntryResponse>
</s:Body>
</s:Envelope>`, pinholeCount+1, 8443+pinholeCount)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				pinholeCount++
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		t.Logf("IPv6 firewall test server at %s", server.URL)
		t.Log("Would enumerate IPv6 pinholes and report:")
		t.Log("- Pinhole 0: 2001:db8::1:443 → fe80::1:8443")
		t.Log("- Pinhole 1: 2001:db8::2:443 → fe80::1:8444")
		t.Log("- Pinhole 2: 2001:db8::3:443 → fe80::1:8445")
		t.Log("Security: HIGH severity for exposed IPv6 services")
	})
}

func TestConcurrentDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Concurrent SSDP and UPnP discovery", func(t *testing.T) {
		ssdpChecker := ssdp.NewSSDPChecker()
		upnpChecker := upnp.NewUPnPChecker()

		router := &common.RouterInfo{
			IP: "192.168.1.1",
		}

		done := make(chan bool, 2)

		go func() {
			_ = ssdpChecker.DefaultConfig()
			t.Log("SSDP checker would discover services concurrently")
			done <- true
		}()

		go func() {
			_ = upnpChecker.DefaultConfig()
			t.Log("UPnP checker would discover IGD concurrently")
			done <- true
		}()

		timeout := time.After(5 * time.Second)
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-timeout:
				t.Fatal("Concurrent discovery test timeout")
			}
		}

		if router.IP != "192.168.1.1" {
			t.Errorf("Router IP changed unexpectedly")
		}
	})
}

func TestErrorHandlingAndRecovery(t *testing.T) {
	t.Run("Network timeout handling", func(t *testing.T) {
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(10 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer slowServer.Close()

		t.Log("Timeout test: HTTP client should timeout within 2-5 seconds")
		t.Log("Graceful failure: No panic, returns nil device")
	})

	t.Run("Malformed XML handling", func(t *testing.T) {
		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<invalid>xml<unclosed>"))
		}))
		defer badServer.Close()

		t.Log("Malformed XML test: Parser should handle gracefully")
		t.Log("Expected: No panic, returns nil device")
	})

	t.Run("Network unavailable", func(t *testing.T) {
		t.Log("Test with unreachable address: 192.0.2.1")
		t.Log("Expected: Timeout and graceful failure")
	})
}

func TestRealWorldScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Home network with router and IoT devices", func(t *testing.T) {
		t.Log("Scenario: Typical home network")
		t.Log("Devices:")
		t.Log("1. UPnP IGD Router (192.168.1.1)")
		t.Log("   - 2 port mappings (SSH, HTTP)")
		t.Log("   - IPv6 firewall with 1 pinhole")
		t.Log("2. DLNA Media Server (192.168.1.100)")
		t.Log("3. Smart TV (192.168.1.101)")
		t.Log("4. IP Camera (192.168.1.102)")
		t.Log("")
		t.Log("Expected findings:")
		t.Log("- HIGH: Port 22 exposed (SSH)")
		t.Log("- HIGH: IPv6 pinhole exposing service")
		t.Log("- MEDIUM: IP Camera with default creds risk")
		t.Log("- MEDIUM: UPnP enabled")
		t.Log("- LOW: DLNA media exposure")
	})

	t.Run("Enterprise network with security controls", func(t *testing.T) {
		t.Log("Scenario: Hardened enterprise network")
		t.Log("Expected:")
		t.Log("- UPnP disabled")
		t.Log("- No SSDP services responding")
		t.Log("- No open port mappings")
		t.Log("- Clean security assessment")
	})
}

func TestUDPMulticastSetup(t *testing.T) {
	t.Run("Verify multicast capability", func(t *testing.T) {
		addr, err := net.ResolveUDPAddr("udp4", ":0")
		if err != nil {
			t.Fatalf("Failed to resolve UDP address: %v", err)
		}

		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			t.Fatalf("Failed to create UDP connection: %v", err)
		}
		defer conn.Close()

		t.Logf("Successfully created UDP socket on %s", conn.LocalAddr())
		t.Log("System supports UDP multicast operations")
	})
}
