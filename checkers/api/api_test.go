package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/output"
)

func TestCheckRouterAPIs(t *testing.T) {
	tests := []struct {
		name          string
		endpoints     map[string]int
		expectIssues  int
		expectHighSev bool
	}{
		{
			name: "No exposed APIs",
			endpoints: map[string]int{
				"/api/":       404,
				"/cgi-bin/":   404,
				"/status.xml": 404,
			},
			expectIssues:  0,
			expectHighSev: false,
		},
		{
			name: "CGI-bin exposed (HIGH severity)",
			endpoints: map[string]int{
				"/cgi-bin/": 200,
				"/api/":     404,
			},
			expectIssues:  1,
			expectHighSev: true,
		},
		{
			name: "TR-069 management exposed (HIGH severity)",
			endpoints: map[string]int{
				"/tr069": 200,
			},
			expectIssues:  1,
			expectHighSev: true,
		},
		{
			name: "Remote management exposed (HIGH severity)",
			endpoints: map[string]int{
				"/remote/": 200,
			},
			expectIssues:  1,
			expectHighSev: true,
		},
		{
			name: "Multiple high severity endpoints",
			endpoints: map[string]int{
				"/cgi-bin/": 200,
				"/tr069":    200,
				"/remote/":  200,
			},
			expectIssues:  3,
			expectHighSev: true,
		},
		{
			name: "Low severity endpoints only",
			endpoints: map[string]int{
				"/status.xml": 200,
				"/info.html":  200,
			},
			expectIssues:  0,
			expectHighSev: false,
		},
		{
			name: "Medium severity endpoints",
			endpoints: map[string]int{
				"/system.xml":   200,
				"/wan.xml":      200,
				"/wireless.xml": 200,
			},
			expectIssues:  0,
			expectHighSev: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status, exists := tt.endpoints[r.URL.Path]; exists {
					w.WriteHeader(status)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			router := &common.RouterInfo{
				IP: server.URL[7:],
			}

			out := output.NewNoOpOutput()
			checkRouterAPIs(router, out)

			if len(router.Issues) != tt.expectIssues {
				t.Errorf("Expected %d issues, got %d", tt.expectIssues, len(router.Issues))
			}

			if tt.expectHighSev {
				hasHighSev := false
				for _, issue := range router.Issues {
					if issue.Severity == common.SeverityHigh {
						hasHighSev = true
						break
					}
				}
				if !hasHighSev {
					t.Error("Expected at least one HIGH severity issue")
				}
			}
		})
	}
}

func TestCheckWPS(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		content     string
		statusCode  int
		expectIssue bool
	}{
		{
			name:        "WPS enabled detected",
			path:        "/wps.html",
			content:     `<html><body><h1>WPS Configuration</h1><p>Status: <b>Enabled</b></p></body></html>`,
			statusCode:  http.StatusOK,
			expectIssue: true,
		},
		{
			name:        "WPS enabled case insensitive",
			path:        "/wireless_wps.html",
			content:     `<html><body>WPS IS ENABLED on your router</body></html>`,
			statusCode:  http.StatusOK,
			expectIssue: true,
		},
		{
			name:        "WPS page exists but disabled",
			path:        "/wps.html",
			content:     `<html><body><h1>WPS Configuration</h1><p>Status: Disabled</p></body></html>`,
			statusCode:  http.StatusOK,
			expectIssue: false,
		},
		{
			name:        "WPS page not found",
			path:        "/wps.html",
			content:     "",
			statusCode:  http.StatusNotFound,
			expectIssue: false,
		},
		{
			name:        "WPS page requires auth",
			path:        "/wps.html",
			content:     "",
			statusCode:  http.StatusUnauthorized,
			expectIssue: false,
		},
		{
			name:        "WPS mentioned but not enabled",
			path:        "/wps_setup.html",
			content:     `<html><body>Configure WPS settings here. Currently off.</body></html>`,
			statusCode:  http.StatusOK,
			expectIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.path {
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(tt.content))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			router := &common.RouterInfo{
				IP: server.URL[7:],
			}

			out := output.NewNoOpOutput()
			checkWPS(router, out)

			hasWPSIssue := false
			for _, issue := range router.Issues {
				if issue.Description == "WPS (WiFi Protected Setup) may be enabled" {
					hasWPSIssue = true
					if issue.Severity != common.SeverityMedium {
						t.Errorf("Expected MEDIUM severity for WPS issue, got %s", issue.Severity)
					}
					break
				}
			}

			if tt.expectIssue && !hasWPSIssue {
				t.Error("Expected WPS security issue but got none")
			}
			if !tt.expectIssue && hasWPSIssue {
				t.Error("Did not expect WPS issue but got one")
			}
		})
	}
}

func TestAPIEndpointsData(t *testing.T) {
	t.Run("All endpoints have required fields", func(t *testing.T) {
		for _, endpoint := range routerAPIEndpoints {
			if endpoint.Path == "" {
				t.Error("Endpoint has empty path")
			}
			if endpoint.Description == "" {
				t.Errorf("Endpoint %s has empty description", endpoint.Path)
			}
			if endpoint.Severity == "" {
				t.Errorf("Endpoint %s has empty severity", endpoint.Path)
			}
			if endpoint.Severity != common.SeverityLow &&
				endpoint.Severity != common.SeverityMedium &&
				endpoint.Severity != common.SeverityHigh &&
				endpoint.Severity != common.SeverityCritical {
				t.Errorf("Endpoint %s has invalid severity: %s", endpoint.Path, endpoint.Severity)
			}
		}
	})

	t.Run("Critical endpoints have HIGH severity", func(t *testing.T) {
		criticalPaths := []string{"/cgi-bin/", "/tr069", "/remote/"}
		for _, path := range criticalPaths {
			found := false
			for _, endpoint := range routerAPIEndpoints {
				if endpoint.Path == path {
					found = true
					if endpoint.Severity != common.SeverityHigh {
						t.Errorf("Critical path %s should have HIGH severity, got %s", path, endpoint.Severity)
					}
					break
				}
			}
			if !found {
				t.Errorf("Critical path %s not found in routerAPIEndpoints", path)
			}
		}
	})
}

func TestWPSPathsData(t *testing.T) {
	t.Run("WPS paths are non-empty", func(t *testing.T) {
		if len(wpsPaths) == 0 {
			t.Error("No WPS paths defined")
		}
		for _, path := range wpsPaths {
			if path == "" {
				t.Error("Empty WPS path found")
			}
			if path[0] != '/' {
				t.Errorf("WPS path %s should start with /", path)
			}
		}
	})

	t.Run("Expected WPS paths exist", func(t *testing.T) {
		expectedPaths := []string{"/wps.html", "/wireless_wps.html"}
		for _, expected := range expectedPaths {
			found := false
			for _, path := range wpsPaths {
				if path == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected WPS path %s not found", expected)
			}
		}
	})
}

func TestAPIChecker_Interface(t *testing.T) {
	checker := NewAPIChecker()

	if checker.Name() != "api" {
		t.Errorf("Name() = %v, want api", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	_, ok := config.(APIConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return APIConfig")
	}
}

func TestAPICheckerHTTPErrors(t *testing.T) {
	t.Run("Server connection failures", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping slow timeout test in short mode")
		}
		router := &common.RouterInfo{
			IP: "192.0.2.1",
		}

		out := output.NewNoOpOutput()
		checkRouterAPIs(router, out)

		if len(router.Issues) > 0 {
			t.Error("Should not report issues when server is unreachable")
		}
	})

	t.Run("Non-200 status codes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cgi-bin/":
				w.WriteHeader(http.StatusForbidden)
			case "/api/":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		router := &common.RouterInfo{
			IP: server.URL[7:],
		}

		out := output.NewNoOpOutput()
		checkRouterAPIs(router, out)

		if len(router.Issues) > 0 {
			t.Error("Should not report issues for non-200 status codes")
		}
	})
}

func TestMultipleAPIEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/":
			w.WriteHeader(http.StatusOK)
		case "/tr069":
			w.WriteHeader(http.StatusOK)
		case "/remote/":
			w.WriteHeader(http.StatusOK)
		case "/status.xml":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	router := &common.RouterInfo{
		IP: server.URL[7:],
	}

	out := output.NewNoOpOutput()
	checkRouterAPIs(router, out)

	if len(router.Issues) != 3 {
		t.Errorf("Expected 3 HIGH severity issues, got %d issues", len(router.Issues))
	}

	for _, issue := range router.Issues {
		if issue.Severity != common.SeverityHigh {
			t.Errorf("All issues should be HIGH severity, got %s", issue.Severity)
		}
	}
}

func BenchmarkCheckRouterAPIs(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	router := &common.RouterInfo{
		IP: server.URL[7:],
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Issues = nil
		out := output.NewNoOpOutput()
		checkRouterAPIs(router, out)
	}
}

func BenchmarkCheckWPS(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	router := &common.RouterInfo{
		IP: server.URL[7:],
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.Issues = nil
		out := output.NewNoOpOutput()
		checkWPS(router, out)
	}
}
