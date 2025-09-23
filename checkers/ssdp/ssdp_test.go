package ssdp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/R167/netcheck/checkers/common"
)

func TestParseSSDPResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     *common.SSDPService
	}{
		{
			name: "valid response with all fields",
			response: "HTTP/1.1 200 OK\r\n" +
				"LOCATION: http://192.168.1.1:5000/description.xml\r\n" +
				"SERVER: Linux/5.4 UPnP/1.1 MiniDLNA/1.2.1\r\n" +
				"USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:MediaServer:1\r\n" +
				"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n",
			want: &common.SSDPService{
				Location:   "http://192.168.1.1:5000/description.xml",
				Server:     "Linux/5.4 UPnP/1.1 MiniDLNA/1.2.1",
				USN:        "uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:MediaServer:1",
				DeviceType: "urn:schemas-upnp-org:device:MediaServer:1",
				IPVersion:  "IPv4",
			},
		},
		{
			name: "response with only location",
			response: "HTTP/1.1 200 OK\r\n" +
				"LOCATION: http://192.168.1.2:1900/desc.xml\r\n\r\n",
			want: &common.SSDPService{
				Location:  "http://192.168.1.2:1900/desc.xml",
				IPVersion: "IPv4",
			},
		},
		{
			name: "response with only USN",
			response: "HTTP/1.1 200 OK\r\n" +
				"USN: uuid:abcdef-12345\r\n\r\n",
			want: &common.SSDPService{
				USN:       "uuid:abcdef-12345",
				IPVersion: "IPv4",
			},
		},
		{
			name:     "invalid response - no location or USN",
			response: "HTTP/1.1 200 OK\r\nSERVER: Test\r\n\r\n",
			want:     nil,
		},
		{
			name:     "empty response",
			response: "",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSDPResponse(tt.response, "IPv4")
			if (got == nil) != (tt.want == nil) {
				t.Errorf("parseSSDPResponse() = %v, want %v", got, tt.want)
				return
			}
			if got != nil && tt.want != nil {
				if got.Location != tt.want.Location {
					t.Errorf("Location = %v, want %v", got.Location, tt.want.Location)
				}
				if got.Server != tt.want.Server {
					t.Errorf("Server = %v, want %v", got.Server, tt.want.Server)
				}
				if got.USN != tt.want.USN {
					t.Errorf("USN = %v, want %v", got.USN, tt.want.USN)
				}
				if got.DeviceType != tt.want.DeviceType {
					t.Errorf("DeviceType = %v, want %v", got.DeviceType, tt.want.DeviceType)
				}
			}
		})
	}
}

func TestCategorizeService(t *testing.T) {
	tests := []struct {
		name    string
		service common.SSDPService
		want    string
	}{
		{
			name: "DLNA media server",
			service: common.SSDPService{
				DeviceType: "urn:schemas-upnp-org:device:MediaServer:1",
			},
			want: "🎬 Media Servers (DLNA)",
		},
		{
			name: "DLNA by name",
			service: common.SSDPService{
				FriendlyName: "My DLNA Server",
			},
			want: "🎬 Media Servers (DLNA)",
		},
		{
			name: "Chromecast",
			service: common.SSDPService{
				FriendlyName: "Living Room Chromecast",
			},
			want: "📺 Media Renderers",
		},
		{
			name: "Network camera",
			service: common.SSDPService{
				DeviceType: "urn:schemas-upnp-org:device:Camera:1",
			},
			want: "📷 Cameras",
		},
		{
			name: "Printer",
			service: common.SSDPService{
				DeviceType: "urn:schemas-upnp-org:device:Printer:1",
			},
			want: "🖨️  Printers",
		},
		{
			name: "NAS device",
			service: common.SSDPService{
				FriendlyName: "Synology NAS",
			},
			want: "💾 Network Storage",
		},
		{
			name: "Router/Gateway",
			service: common.SSDPService{
				DeviceType: "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
			},
			want: "🌐 Gateways/Routers",
		},
		{
			name: "Smart bulb",
			service: common.SSDPService{
				FriendlyName: "Philips Hue Light",
			},
			want: "💡 Smart Home Devices",
		},
		{
			name: "Thermostat",
			service: common.SSDPService{
				FriendlyName: "Smart Thermostat",
			},
			want: "🌡️  Sensors/Thermostats",
		},
		{
			name: "Unknown device",
			service: common.SSDPService{
				DeviceType: "urn:custom:device:Unknown:1",
			},
			want: "📦 Other Devices",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeService(tt.service)
			if got != tt.want {
				t.Errorf("categorizeService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnrichServiceInfo(t *testing.T) {
	deviceXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
		<friendlyName>Test Media Server</friendlyName>
		<manufacturer>Test Manufacturer</manufacturer>
		<modelName>Test Model</modelName>
	</device>
</root>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(deviceXML))
	}))
	defer server.Close()

	ssdp := &common.SSDPService{
		Location: server.URL,
	}

	enrichServiceInfo(ssdp)

	if ssdp.FriendlyName != "Test Media Server" {
		t.Errorf("FriendlyName = %v, want Test Media Server", ssdp.FriendlyName)
	}
	if ssdp.Manufacturer != "Test Manufacturer" {
		t.Errorf("Manufacturer = %v, want Test Manufacturer", ssdp.Manufacturer)
	}
	if ssdp.ModelName != "Test Model" {
		t.Errorf("ModelName = %v, want Test Model", ssdp.ModelName)
	}
}

func TestEnrichServiceInfo_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid xml"))
	}))
	defer server.Close()

	ssdp := &common.SSDPService{
		Location:     server.URL,
		FriendlyName: "Original Name",
	}

	enrichServiceInfo(ssdp)

	if ssdp.FriendlyName != "Original Name" {
		t.Errorf("FriendlyName should remain unchanged on invalid XML")
	}
}

func TestEnrichServiceInfo_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ssdp := &common.SSDPService{
		Location: server.URL,
	}

	start := time.Now()
	enrichServiceInfo(ssdp)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("enrichServiceInfo should timeout, took %v", elapsed)
	}
}

func TestSSDPMulticastDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Skip("Multicast discovery requires specific network setup - tested manually")
}

func TestAssessSecurityRisks(t *testing.T) {
	router := &common.RouterInfo{}

	categorized := map[string][]common.SSDPService{
		"🎬 Media Servers (DLNA)": {
			{FriendlyName: "Media Server 1"},
			{FriendlyName: "Media Server 2"},
		},
		"📷 Cameras": {
			{FriendlyName: "Camera 1"},
		},
		"💾 Network Storage": {
			{FriendlyName: "NAS 1"},
		},
		"💡 Smart Home Devices": {
			{FriendlyName: "Smart Bulb 1"},
		},
	}

	assessSecurityRisks(router, categorized)

	if len(router.Issues) != 4 {
		t.Errorf("Expected 4 security issues, got %d", len(router.Issues))
	}

	severityCounts := make(map[string]int)
	for _, issue := range router.Issues {
		severityCounts[issue.Severity]++
	}

	if severityCounts[common.SeverityLow] != 2 {
		t.Errorf("Expected 2 LOW severity issues, got %d", severityCounts[common.SeverityLow])
	}
	if severityCounts[common.SeverityMedium] != 2 {
		t.Errorf("Expected 2 MEDIUM severity issues, got %d", severityCounts[common.SeverityMedium])
	}
}

func TestSSDPChecker_Interface(t *testing.T) {
	checker := NewSSDPChecker()

	if checker.Name() != "ssdp" {
		t.Errorf("Name() = %v, want ssdp", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return false")
	}

	config := checker.DefaultConfig()
	ssdpConfig, ok := config.(SSDPConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return SSDPConfig")
	}

	if !ssdpConfig.IPv4Enabled {
		t.Error("IPv4Enabled should be true by default")
	}
	if !ssdpConfig.IPv6Enabled {
		t.Error("IPv6Enabled should be true by default")
	}
	if len(ssdpConfig.SearchTargets) != 1 || ssdpConfig.SearchTargets[0] != "ssdp:all" {
		t.Error("SearchTargets should default to ['ssdp:all']")
	}
}

func BenchmarkParseSSDPResponse(b *testing.B) {
	response := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.1:5000/description.xml\r\n" +
		"SERVER: Linux/5.4 UPnP/1.1 MiniDLNA/1.2.1\r\n" +
		"USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseSSDPResponse(response, "IPv4")
	}
}

func BenchmarkCategorizeService(b *testing.B) {
	service := common.SSDPService{
		DeviceType:   "urn:schemas-upnp-org:device:MediaServer:1",
		FriendlyName: "My DLNA Media Server",
		Manufacturer: "TestCorp",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		categorizeService(service)
	}
}
