package web

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/internal/checker"
	"github.com/R167/netcheck/internal/output"
)

type WebChecker struct{}

type WebConfig struct {
	CheckDefaultCreds bool
}

type DefaultCred struct {
	Username string
	Password string
}

var (
	linksysPattern   = regexp.MustCompile(`(?i)linksys|smart\s*wi-fi`)
	netgearPattern   = regexp.MustCompile(`(?i)netgear|genie`)
	dlinkPattern     = regexp.MustCompile(`(?i)d-link|dir-\d+`)
	tplinkPattern    = regexp.MustCompile(`(?i)tp-link|tl-\w+`)
	asusPattern      = regexp.MustCompile(`(?i)asus|rt-\w+`)
	ciscoPattern     = regexp.MustCompile(`(?i)cisco|linksys`)
	belkinPattern    = regexp.MustCompile(`(?i)belkin|play max`)
	motorolaPattern  = regexp.MustCompile(`(?i)motorola|surfboard`)
	xfinityPattern   = regexp.MustCompile(`(?i)xfinity|comcast|technicolor`)
	arrisPattern     = regexp.MustCompile(`(?i)arris|surfboard`)
	huaweiPattern    = regexp.MustCompile(`(?i)huawei|echolife`)
	ztePattern       = regexp.MustCompile(`(?i)zte`)
	actiontecPattern = regexp.MustCompile(`(?i)actiontec|verizon`)
	titlePattern     = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
)

var vendorPatterns = map[string]*regexp.Regexp{
	"linksys":   linksysPattern,
	"netgear":   netgearPattern,
	"dlink":     dlinkPattern,
	"tplink":    tplinkPattern,
	"asus":      asusPattern,
	"cisco":     ciscoPattern,
	"belkin":    belkinPattern,
	"motorola":  motorolaPattern,
	"xfinity":   xfinityPattern,
	"arris":     arrisPattern,
	"huawei":    huaweiPattern,
	"zte":       ztePattern,
	"actiontec": actiontecPattern,
}

var defaultCredentials = map[string][]DefaultCred{
	"linksys": {
		{Username: "admin", Password: "admin"},
		{Username: "", Password: "admin"},
		{Username: "admin", Password: ""},
	},
	"netgear": {
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "1234"},
	},
	"dlink": {
		{Username: "admin", Password: ""},
		{Username: "admin", Password: "admin"},
		{Username: "user", Password: ""},
	},
	"tplink": {
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
	},
	"asus": {
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
	},
	"cisco": {
		{Username: "admin", Password: "admin"},
		{Username: "cisco", Password: "cisco"},
		{Username: "admin", Password: "password"},
	},
	"belkin": {
		{Username: "", Password: ""},
		{Username: "admin", Password: ""},
		{Username: "admin", Password: "admin"},
	},
	"motorola": {
		{Username: "admin", Password: "motorola"},
		{Username: "admin", Password: "admin"},
	},
	"xfinity": {
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "admin"},
		{Username: "comcast", Password: "1234"},
		{Username: "cusadmin", Password: "password"},
		{Username: "cusadmin", Password: "highspeed"},
	},
	"arris": {
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "arris"},
		{Username: "", Password: ""},
	},
	"huawei": {
		{Username: "admin", Password: "admin"},
		{Username: "root", Password: "admin"},
		{Username: "user", Password: "user"},
		{Username: "admin", Password: ""},
	},
	"zte": {
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
		{Username: "user", Password: "user"},
		{Username: "admin", Password: "zhone"},
	},
	"actiontec": {
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "admin"},
		{Username: "", Password: ""},
	},
}

var defaultPageIndicators = []string{
	"welcome to your new router",
	"initial setup",
	"quick setup wizard",
	"router configuration",
	"default password",
	"change default password",
	"setup wizard",
}

func NewWebChecker() checker.Checker {
	return &WebChecker{}
}

func (c *WebChecker) Name() string {
	return "web"
}

func (c *WebChecker) Description() string {
	return "Web interface and default credentials"
}

func (c *WebChecker) Icon() string {
	return "🔍"
}

func (c *WebChecker) DefaultConfig() checker.CheckerConfig {
	return WebConfig{
		CheckDefaultCreds: true,
	}
}

func (c *WebChecker) RequiresRouter() bool {
	return true
}

func (c *WebChecker) DefaultEnabled() bool {
	return true
}

func (c *WebChecker) Dependencies() []checker.Dependency {
	return []checker.Dependency{checker.DependencyGateway, checker.DependencyRouterInfo}
}

func (c *WebChecker) Run(config checker.CheckerConfig, router *common.RouterInfo, out output.Output) {
	cfg := config.(WebConfig)
	checkWebInterface(router, cfg, out)
}

func (c *WebChecker) RunStandalone(config checker.CheckerConfig, out output.Output) {
}

func (c *WebChecker) MCPToolDefinition() *checker.MCPTool {
	return &checker.MCPTool{
		Name:        "check_web_interface",
		Description: "Check router web interface for default credentials and security issues",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"gateway_ip": map[string]interface{}{
					"type":        "string",
					"description": "The IP address of the router gateway",
				},
				"check_default_creds": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to test default credentials",
					"default":     true,
				},
			},
			"required": []string{"gateway_ip"},
		},
	}
}

func checkWebInterface(router *common.RouterInfo, cfg WebConfig, out output.Output) {
	out.Section("🔍", "Checking web interface...")

	client := &http.Client{
		Timeout: common.HTTPTimeout,
	}

	urls := []string{
		fmt.Sprintf("http://%s", router.IP),
		fmt.Sprintf("https://%s", router.IP),
		fmt.Sprintf("http://%s:8080", router.IP),
		fmt.Sprintf("https://%s:8443", router.IP),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		router.WebInterface = true
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		content := string(body)
		detectVendor(router, content, out)
		checkDefaultPage(router, content, url, out)
		if cfg.CheckDefaultCreds {
			checkDefaultCredentials(router, url, out)
		}
		break
	}

	if !router.WebInterface {
		out.Info("ℹ️  No web interface detected")
	}
}

func detectVendor(router *common.RouterInfo, content string, out output.Output) {
	for vendor, pattern := range vendorPatterns {
		if pattern.MatchString(content) {
			router.Vendor = vendor
			out.Info("📱 Detected vendor: %s", strings.Title(vendor))
			break
		}
	}

	if matches := titlePattern.FindStringSubmatch(content); len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if router.Vendor == "" && title != "" {
			out.Info("📄 Page title: %s", title)
		}
	}
}

func checkDefaultPage(router *common.RouterInfo, content, url string, out output.Output) {
	contentLower := strings.ToLower(content)
	for _, indicator := range defaultPageIndicators {
		if strings.Contains(contentLower, indicator) {
			router.Issues = append(router.Issues, common.SecurityIssue{
				Severity:    common.SeverityHigh,
				Description: "Default setup page detected",
				Details:     fmt.Sprintf("Router appears to be using default configuration at %s", url),
			})
			out.Warning("Default setup page detected")
			return
		}
	}
}

func checkDefaultCredentials(router *common.RouterInfo, baseURL string, out output.Output) {
	if router.Vendor == "" {
		return
	}

	creds, exists := defaultCredentials[router.Vendor]
	if !exists {
		return
	}

	out.Info("🔐 Testing default credentials for %s...", router.Vendor)

	client := &http.Client{
		Timeout: common.HTTPTimeout,
	}

	for _, cred := range creds {
		if testCredentials(client, baseURL, cred.Username, cred.Password) {
			router.DefaultCreds = true
			router.Issues = append(router.Issues, common.SecurityIssue{
				Severity:    common.SeverityCritical,
				Description: "Default credentials are active",
				Details:     fmt.Sprintf("Username: '%s', Password: '%s'", cred.Username, cred.Password),
			})
			out.Error("🚨 Default credentials work: %s/%s", cred.Username, cred.Password)
			return
		}
	}

	out.Success("Default credentials not working")
}

func testCredentials(client *http.Client, baseURL, username, password string) bool {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
