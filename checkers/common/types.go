package common

import "time"

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

const (
	HTTPTimeout   = 5 * time.Second
	PortTimeout   = 1 * time.Second
	NATpmpTimeout = 3 * time.Second
)

var SeverityOrder = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
}

type SecurityIssue struct {
	Severity    string
	Description string
	Details     string
}

type RouterInfo struct {
	IP            string
	Vendor        string
	Model         string
	SerialNumber  string
	ExternalIP    string
	WebInterface  bool
	DefaultCreds  bool
	OpenPorts     []int
	UPnPEnabled   bool
	NATpmpEnabled bool
	IPv6Enabled   bool
	MDNSEnabled   bool
	SSDPEnabled   bool
	PortMappings  []PortMapping
	IPv6Pinholes  []IPv6Pinhole
	UPnPServices  []UPnPService
	SSDPServices  []SSDPService
	MDNSServices  []MDNSService
	Issues        []SecurityIssue
	Starlink      interface{}
}

type PortMapping struct {
	ExternalPort int
	InternalIP   string
	InternalPort int
	Protocol     string
	Description  string
}

type UPnPDevice struct {
	DeviceType      string `xml:"device>deviceType"`
	FriendlyName    string `xml:"device>friendlyName"`
	Manufacturer    string `xml:"device>manufacturer"`
	ModelName       string `xml:"device>modelName"`
	ModelNumber     string `xml:"device>modelNumber"`
	SerialNumber    string `xml:"device>serialNumber"`
	PresentationURL string `xml:"device>presentationURL"`
}

type SSDPResponse struct {
	Location string
	Server   string
	USN      string
}

type MDNSService struct {
	Name    string
	Type    string
	Domain  string
	IP      string
	Port    int
	TXTData []string
}

type IPv6Pinhole struct {
	RemoteHost   string
	RemotePort   int
	InternalHost string
	InternalPort int
	Protocol     string
	LeaseTime    int
	Description  string
}

type UPnPService struct {
	ServiceType string
	ServiceID   string
	ControlURL  string
	EventSubURL string
	SCPDURL     string
	IsStandard  bool
}

type SSDPService struct {
	DeviceType   string
	FriendlyName string
	Manufacturer string
	ModelName    string
	Location     string
	Server       string
	USN          string
	Category     string
	IPVersion    string
}
