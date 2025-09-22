package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/R167/netcheck/checkers/common"
)

func TestDetectVendor(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "Linksys router",
			content: `<html><title>Smart Wi-Fi Router</title></html>`,
			want:    "linksys",
		},
		{
			name:    "Netgear router",
			content: `<html><body>Welcome to NETGEAR Genie</body></html>`,
			want:    "netgear",
		},
		{
			name:    "D-Link router",
			content: `<html><title>D-Link DIR-825 Router</title></html>`,
			want:    "dlink",
		},
		{
			name:    "TP-Link router",
			content: `<html><body>TP-LINK TL-WR940N Wireless Router</body></html>`,
			want:    "tplink",
		},
		{
			name:    "ASUS router",
			content: `<html><title>ASUS RT-AC68U</title></html>`,
			want:    "asus",
		},
		{
			name:    "Cisco router",
			content: `<html><title>Cisco Router Configuration</title></html>`,
			want:    "cisco",
		},
		{
			name:    "Unknown vendor",
			content: `<html><title>Router Login</title></html>`,
			want:    "",
		},
		{
			name:    "Case insensitive",
			content: `<html><title>NETGEAR router</title></html>`,
			want:    "netgear",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &common.RouterInfo{}
			detectVendor(router, tt.content)
			if router.Vendor != tt.want {
				t.Errorf("detectVendor() vendor = %v, want %v", router.Vendor, tt.want)
			}
		})
	}
}

func TestCheckDefaultPage(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectIssue bool
	}{
		{
			name:        "Default setup wizard",
			content:     `<html><body>Welcome to your new router. Please complete the quick setup wizard.</body></html>`,
			expectIssue: true,
		},
		{
			name:        "Default password warning",
			content:     `<html><body>Please change default password</body></html>`,
			expectIssue: true,
		},
		{
			name:        "Initial setup page",
			content:     `<html><title>Initial Setup - Router Configuration</title></html>`,
			expectIssue: true,
		},
		{
			name:        "Normal login page",
			content:     `<html><title>Router Login</title><body>Please login</body></html>`,
			expectIssue: false,
		},
		{
			name:        "Case insensitive detection",
			content:     `<html><body>WELCOME TO YOUR NEW ROUTER</body></html>`,
			expectIssue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := &common.RouterInfo{}
			checkDefaultPage(router, tt.content, "http://192.168.1.1")

			hasIssue := len(router.Issues) > 0
			if hasIssue != tt.expectIssue {
				t.Errorf("checkDefaultPage() issue detected = %v, want %v", hasIssue, tt.expectIssue)
			}

			if tt.expectIssue && len(router.Issues) > 0 {
				if router.Issues[0].Severity != common.SeverityHigh {
					t.Errorf("Expected HIGH severity, got %s", router.Issues[0].Severity)
				}
			}
		})
	}
}

func TestTestCredentials(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		password       string
		serverResponse int
		want           bool
	}{
		{
			name:           "Valid credentials",
			username:       "admin",
			password:       "admin",
			serverResponse: http.StatusOK,
			want:           true,
		},
		{
			name:           "Invalid credentials",
			username:       "admin",
			password:       "wrong",
			serverResponse: http.StatusUnauthorized,
			want:           false,
		},
		{
			name:           "Empty username",
			username:       "",
			password:       "admin",
			serverResponse: http.StatusOK,
			want:           true,
		},
		{
			name:           "Empty password",
			username:       "admin",
			password:       "",
			serverResponse: http.StatusOK,
			want:           true,
		},
		{
			name:           "Server error",
			username:       "admin",
			password:       "admin",
			serverResponse: http.StatusInternalServerError,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			client := &http.Client{}
			got := testCredentials(client, server.URL, tt.username, tt.password)
			if got != tt.want {
				t.Errorf("testCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckDefaultCredentials(t *testing.T) {
	t.Run("Linksys with default creds", func(t *testing.T) {
		successCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "Basic YWRtaW46YWRtaW4=" { // admin:admin in base64
				w.WriteHeader(http.StatusOK)
				successCount++
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}))
		defer server.Close()

		router := &common.RouterInfo{
			Vendor: "linksys",
		}

		checkDefaultCredentials(router, server.URL)

		if !router.DefaultCreds {
			t.Error("Expected DefaultCreds to be true")
		}
		if len(router.Issues) == 0 {
			t.Error("Expected security issue to be reported")
		}
		if len(router.Issues) > 0 && router.Issues[0].Severity != common.SeverityCritical {
			t.Errorf("Expected CRITICAL severity, got %s", router.Issues[0].Severity)
		}
		if successCount != 1 {
			t.Errorf("Expected 1 successful auth, got %d", successCount)
		}
	})

	t.Run("Unknown vendor", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := &common.RouterInfo{
			Vendor: "",
		}

		checkDefaultCredentials(router, server.URL)

		if router.DefaultCreds {
			t.Error("Expected DefaultCreds to be false for unknown vendor")
		}
	})

	t.Run("No default creds work", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		router := &common.RouterInfo{
			Vendor: "netgear",
		}

		checkDefaultCredentials(router, server.URL)

		if router.DefaultCreds {
			t.Error("Expected DefaultCreds to be false when no creds work")
		}
	})
}

func TestCheckWebInterface_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Linksys router with default setup page", func(t *testing.T) {
		html := `<html>
		<head><title>Smart Wi-Fi Router Setup</title></head>
		<body>
			<h1>Welcome to your new router</h1>
			<p>Please complete the quick setup wizard to configure your router.</p>
		</body>
		</html>`

		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			auth := r.Header.Get("Authorization")
			if auth == "Basic YWRtaW46YWRtaW4=" {
				w.WriteHeader(http.StatusOK)
			} else if auth == "" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(html))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}))
		defer server.Close()

		router := &common.RouterInfo{
			IP: server.URL[7:], // Remove "http://"
		}

		cfg := WebConfig{CheckDefaultCreds: true}
		checkWebInterface(router, cfg)

		if !router.WebInterface {
			t.Error("Expected WebInterface to be true")
		}
		if router.Vendor != "linksys" {
			t.Errorf("Expected vendor linksys, got %s", router.Vendor)
		}
		if !router.DefaultCreds {
			t.Error("Expected DefaultCreds to be true")
		}

		hasDefaultPage := false
		hasDefaultCreds := false
		for _, issue := range router.Issues {
			if issue.Description == "Default setup page detected" {
				hasDefaultPage = true
			}
			if issue.Description == "Default credentials are active" {
				hasDefaultCreds = true
			}
		}

		if !hasDefaultPage {
			t.Error("Expected default setup page issue")
		}
		if !hasDefaultCreds {
			t.Error("Expected default credentials issue")
		}
	})
}

func TestWebChecker_Interface(t *testing.T) {
	checker := NewWebChecker()

	if checker.Name() != "web" {
		t.Errorf("Name() = %v, want web", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	webConfig, ok := config.(WebConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return WebConfig")
	}

	if !webConfig.CheckDefaultCreds {
		t.Error("CheckDefaultCreds should be true by default")
	}
}

func TestDefaultCredentialsData(t *testing.T) {
	t.Run("All vendors have credentials", func(t *testing.T) {
		vendors := []string{"linksys", "netgear", "dlink", "tplink", "asus", "cisco", "belkin", "motorola", "xfinity", "arris", "huawei", "zte", "actiontec"}

		for _, vendor := range vendors {
			creds, exists := defaultCredentials[vendor]
			if !exists {
				t.Errorf("Vendor %s missing from defaultCredentials", vendor)
			}
			if len(creds) == 0 {
				t.Errorf("Vendor %s has no credentials defined", vendor)
			}
		}
	})

	t.Run("All vendors have patterns", func(t *testing.T) {
		vendors := []string{"linksys", "netgear", "dlink", "tplink", "asus", "cisco", "belkin", "motorola", "xfinity", "arris", "huawei", "zte", "actiontec"}

		for _, vendor := range vendors {
			pattern, exists := vendorPatterns[vendor]
			if !exists {
				t.Errorf("Vendor %s missing from vendorPatterns", vendor)
			}
			if pattern == nil {
				t.Errorf("Vendor %s has nil pattern", vendor)
			}
		}
	})
}

func TestVendorPatternMatching(t *testing.T) {
	tests := []struct {
		vendor  string
		content string
		match   bool
	}{
		{"linksys", "Linksys Smart Wi-Fi", true},
		{"linksys", "LINKSYS", true},
		{"netgear", "NETGEAR Genie", true},
		{"dlink", "D-Link DIR-825", true},
		{"tplink", "TP-LINK TL-WR940N", true},
		{"asus", "ASUS RT-AC68U", true},
		{"cisco", "Cisco Systems", true},
		{"xfinity", "Xfinity xFi", true},
		{"xfinity", "Comcast Gateway", true},
		{"arris", "ARRIS Surfboard", true},
		{"motorola", "Motorola SB6141", true},
		{"linksys", "Netgear Router", false},
		{"netgear", "TP-Link", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%v", tt.vendor, tt.match), func(t *testing.T) {
			pattern := vendorPatterns[tt.vendor]
			if pattern == nil {
				t.Fatalf("Pattern not found for vendor %s", tt.vendor)
			}

			matched := pattern.MatchString(tt.content)
			if matched != tt.match {
				t.Errorf("Pattern for %s matched %v, want %v for content: %s", tt.vendor, matched, tt.match, tt.content)
			}
		})
	}
}

func BenchmarkDetectVendor(b *testing.B) {
	content := `<html>
	<head><title>Linksys Smart Wi-Fi Router</title></head>
	<body>Welcome to Linksys</body>
	</html>`

	router := &common.RouterInfo{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detectVendor(router, content)
	}
}

func BenchmarkCheckDefaultPage(b *testing.B) {
	content := `<html><body>Welcome to your new router. Please complete the setup wizard.</body></html>`
	router := &common.RouterInfo{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Issues = nil
		checkDefaultPage(router, content, "http://192.168.1.1")
	}
}
