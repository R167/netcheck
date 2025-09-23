package upnp

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/output"
)

func TestParseSSDPResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     *common.SSDPResponse
	}{
		{
			name: "valid response with all fields",
			response: "HTTP/1.1 200 OK\r\n" +
				"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n" +
				"SERVER: Linux/5.4 UPnP/2.0 Router/1.0\r\n" +
				"USN: uuid:12345678-90ab-cdef-1234-567890abcdef\r\n\r\n",
			want: &common.SSDPResponse{
				Location: "http://192.168.1.1:5000/rootDesc.xml",
				Server:   "Linux/5.4 UPnP/2.0 Router/1.0",
				USN:      "uuid:12345678-90ab-cdef-1234-567890abcdef",
			},
		},
		{
			name: "case insensitive headers",
			response: "HTTP/1.1 200 OK\r\n" +
				"location: http://router.local/desc.xml\r\n" +
				"server: TestServer/1.0\r\n\r\n",
			want: &common.SSDPResponse{
				Location: "http://router.local/desc.xml",
				Server:   "TestServer/1.0",
			},
		},
		{
			name:     "location with extra spaces",
			response: "LOCATION:   http://example.com/test.xml   \r\n\r\n",
			want: &common.SSDPResponse{
				Location: "http://example.com/test.xml",
			},
		},
		{
			name:     "no location",
			response: "SERVER: Test\r\nUSN: uuid:test\r\n\r\n",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSDPResponse(tt.response)
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
			}
		})
	}
}

func TestParsePortMapping(t *testing.T) {
	soapResponse := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>8080</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>80</NewInternalPort>
<NewInternalClient>192.168.1.100</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Web Server</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>`

	mapping := parsePortMapping(soapResponse)

	if mapping.ExternalPort != 8080 {
		t.Errorf("ExternalPort = %d, want 8080", mapping.ExternalPort)
	}
	if mapping.InternalPort != 80 {
		t.Errorf("InternalPort = %d, want 80", mapping.InternalPort)
	}
	if mapping.InternalIP != "192.168.1.100" {
		t.Errorf("InternalIP = %s, want 192.168.1.100", mapping.InternalIP)
	}
	if mapping.Protocol != "TCP" {
		t.Errorf("Protocol = %s, want TCP", mapping.Protocol)
	}
	if mapping.Description != "Web Server" {
		t.Errorf("Description = %s, want Web Server", mapping.Description)
	}
}

func TestParseIPv6FirewallStatus(t *testing.T) {
	soapResponse := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetFirewallStatusResponse xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1">
<FirewallEnabled>1</FirewallEnabled>
<InboundPinholeAllowed>1</InboundPinholeAllowed>
</u:GetFirewallStatusResponse>
</s:Body>
</s:Envelope>`

	status := parseIPv6FirewallStatusResponse(soapResponse)

	if status == nil {
		t.Fatal("Expected status, got nil")
	}
	if !status.FirewallEnabled {
		t.Error("FirewallEnabled = false, want true")
	}
	if !status.InboundPinholeAllowed {
		t.Error("InboundPinholeAllowed = false, want true")
	}
}

func parseIPv6FirewallStatusResponse(soapResponse string) *IPv6FirewallStatus {
	status := &IPv6FirewallStatus{}

	// Parse FirewallEnabled
	if match := regexp.MustCompile(`<FirewallEnabled>(\d+)</FirewallEnabled>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		status.FirewallEnabled = match[1] == "1"
	}

	// Parse InboundPinholeAllowed
	if match := regexp.MustCompile(`<InboundPinholeAllowed>(\d+)</InboundPinholeAllowed>`).FindStringSubmatch(soapResponse); len(match) > 1 {
		status.InboundPinholeAllowed = match[1] == "1"
	}

	return status
}

func TestGetUPnPDescriptionFromURL(t *testing.T) {
	deviceXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
		<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
		<friendlyName>Test Router</friendlyName>
		<manufacturer>TestCorp</manufacturer>
		<modelName>TR-1000</modelName>
		<modelNumber>v1.0</modelNumber>
		<serialNumber>ABC123456</serialNumber>
		<presentationURL>http://192.168.1.1/</presentationURL>
	</device>
</root>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(deviceXML))
	}))
	defer server.Close()

	device := getUPnPDescriptionFromURL(server.URL)

	if device == nil {
		t.Fatal("Expected device, got nil")
	}
	if device.FriendlyName != "Test Router" {
		t.Errorf("FriendlyName = %s, want Test Router", device.FriendlyName)
	}
	if device.Manufacturer != "TestCorp" {
		t.Errorf("Manufacturer = %s, want TestCorp", device.Manufacturer)
	}
	if device.ModelName != "TR-1000" {
		t.Errorf("ModelName = %s, want TR-1000", device.ModelName)
	}
	if device.SerialNumber != "ABC123456" {
		t.Errorf("SerialNumber = %s, want ABC123456", device.SerialNumber)
	}
}

func TestGetUPnPDescriptionFromURL_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	device := getUPnPDescriptionFromURL(server.URL)

	if device != nil {
		t.Errorf("Expected nil for 404 response, got %v", device)
	}
}

func TestGetUPnPDescriptionFromURL_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not xml"))
	}))
	defer server.Close()

	device := getUPnPDescriptionFromURL(server.URL)

	if device != nil {
		t.Errorf("Expected nil for invalid XML, got %v", device)
	}
}

func TestEnumerateUPnPServices(t *testing.T) {
	deviceXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<device>
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
			<service>
				<serviceType>urn:vendor-specific:service:CustomService:1</serviceType>
				<serviceId>urn:vendor:serviceId:Custom1</serviceId>
				<controlURL>/ctl/Custom</controlURL>
			</service>
		</serviceList>
	</device>
</root>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(deviceXML))
	}))
	defer server.Close()

	router := &common.RouterInfo{}
	out := output.NewNoOpOutput()
	enumerateUPnPServices(router, server.URL, out)

	if len(router.UPnPServices) != 3 {
		t.Errorf("Expected 3 services, got %d", len(router.UPnPServices))
	}

	standardCount := 0
	nonStandardCount := 0
	for _, svc := range router.UPnPServices {
		if svc.IsStandard {
			standardCount++
		} else {
			nonStandardCount++
		}
	}

	if standardCount != 2 {
		t.Errorf("Expected 2 standard services, got %d", standardCount)
	}
	if nonStandardCount != 1 {
		t.Errorf("Expected 1 non-standard service, got %d", nonStandardCount)
	}

	hasIssue := false
	for _, issue := range router.Issues {
		if strings.Contains(issue.Description, "Non-standard") {
			hasIssue = true
			break
		}
	}
	if !hasIssue {
		t.Error("Expected security issue for non-standard service")
	}
}

func TestGetPortMappings_MockServer(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ctl/IPConn" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if callCount == 0 {
			response := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntryResponse>
<NewExternalPort>80</NewExternalPort>
<NewInternalPort>8080</NewInternalPort>
<NewInternalClient>192.168.1.10</NewInternalClient>
<NewProtocol>TCP</NewProtocol>
<NewPortMappingDescription>Test Service</NewPortMappingDescription>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>`
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(response))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		callCount++
	}))
	defer server.Close()

	mappings := getPortMappings(server.URL)

	if len(mappings) != 1 {
		t.Errorf("Expected 1 mapping, got %d", len(mappings))
	}

	if len(mappings) > 0 {
		if mappings[0].ExternalPort != 80 {
			t.Errorf("ExternalPort = %d, want 80", mappings[0].ExternalPort)
		}
		if mappings[0].InternalPort != 8080 {
			t.Errorf("InternalPort = %d, want 8080", mappings[0].InternalPort)
		}
	}
}

func TestGetIPv6FirewallStatus_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ctl/IP6FCtl" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		response := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetFirewallStatusResponse xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1">
<FirewallEnabled>1</FirewallEnabled>
<InboundPinholeAllowed>0</InboundPinholeAllowed>
</u:GetFirewallStatusResponse>
</s:Body>
</s:Envelope>`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	status := getIPv6FirewallStatus(server.URL, "/ctl/IP6FCtl")

	if status == nil {
		t.Fatal("Expected status, got nil")
	}
	if !status.FirewallEnabled {
		t.Error("FirewallEnabled = false, want true")
	}
	if status.InboundPinholeAllowed {
		t.Error("InboundPinholeAllowed = true, want false")
	}
}

func TestUPnPChecker_Interface(t *testing.T) {
	checker := NewUPnPChecker()

	if checker.Name() != "upnp" {
		t.Errorf("Name() = %v, want upnp", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	upnpConfig, ok := config.(UPnPConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return UPnPConfig")
	}

	if !upnpConfig.EnumerateMappings {
		t.Error("EnumerateMappings should be true by default")
	}
	if !upnpConfig.CheckIPv6Firewall {
		t.Error("CheckIPv6Firewall should be true by default")
	}
	if !upnpConfig.EnumerateServices {
		t.Error("EnumerateServices should be true by default")
	}
	if !upnpConfig.CheckSecurityIssues {
		t.Error("CheckSecurityIssues should be true by default")
	}
}

func BenchmarkParseSSDPResponse(b *testing.B) {
	response := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n" +
		"SERVER: Linux/5.4 UPnP/2.0 Router/1.0\r\n" +
		"USN: uuid:12345678-90ab-cdef-1234-567890abcdef\r\n\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseSSDPResponse(response)
	}
}

func BenchmarkParsePortMapping(b *testing.B) {
	soapResponse := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewExternalPort>8080</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>80</NewInternalPort>
<NewInternalClient>192.168.1.100</NewInternalClient>
<NewPortMappingDescription>Web Server</NewPortMappingDescription>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsePortMapping(soapResponse)
	}
}
