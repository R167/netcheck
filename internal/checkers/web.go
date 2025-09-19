package checkers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/R167/netcheck/internal/mcp"
)

const (
	HTTPTimeout = 5 * time.Second
)

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

type WebCheckResult struct {
	Vendor       string
	Model        string
	DefaultCreds bool
	Issues       []mcp.Issue
}

func CheckWebInterface(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
	result := &WebCheckResult{
		Issues: []mcp.Issue{},
	}

	client := &http.Client{
		Timeout: HTTPTimeout,
	}

	urls := []string{
		fmt.Sprintf("http://%s", input.GatewayIP),
		fmt.Sprintf("https://%s", input.GatewayIP),
		fmt.Sprintf("http://%s:8080", input.GatewayIP),
		fmt.Sprintf("https://%s:8443", input.GatewayIP),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		content := string(body)
		detectVendor(result, content)
		checkDefaultPage(result, content, url)

		if input.CheckDefaultCreds && result.Vendor != "" {
			checkDefaultCreds(result, url)
		}
		break
	}

	report := formatWebReport(result, input.GatewayIP)

	return &mcp.CheckToolOutput{
		Issues:  result.Issues,
		Summary: fmt.Sprintf("Found %d issues", len(result.Issues)),
		Report:  report,
	}, nil
}

func detectVendor(result *WebCheckResult, content string) {
	for vendor, pattern := range vendorPatterns {
		if pattern.MatchString(content) {
			result.Vendor = vendor
			return
		}
	}
}

func checkDefaultPage(result *WebCheckResult, content, url string) {
	contentLower := strings.ToLower(content)
	for _, indicator := range defaultPageIndicators {
		if strings.Contains(contentLower, indicator) {
			result.Issues = append(result.Issues, mcp.Issue{
				Severity:    "HIGH",
				Description: "Default setup page detected",
				Details:     fmt.Sprintf("Router appears to be using default configuration at %s", url),
			})
			return
		}
	}
}

func checkDefaultCreds(result *WebCheckResult, baseURL string) {
	creds, exists := defaultCredentials[result.Vendor]
	if !exists {
		return
	}

	client := &http.Client{
		Timeout: HTTPTimeout,
	}

	for _, cred := range creds {
		if testCredentials(client, baseURL, cred.Username, cred.Password) {
			result.DefaultCreds = true
			result.Issues = append(result.Issues, mcp.Issue{
				Severity:    "CRITICAL",
				Description: "Default credentials are active",
				Details:     fmt.Sprintf("Username: '%s', Password: '%s'", cred.Username, cred.Password),
			})
			return
		}
	}
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

func formatWebReport(result *WebCheckResult, ip string) string {
	report := fmt.Sprintf("Router IP: %s\n", ip)

	if result.Vendor != "" {
		report += fmt.Sprintf("Vendor: %s\n", strings.Title(result.Vendor))
	}
	if result.Model != "" {
		report += fmt.Sprintf("Model: %s\n", result.Model)
	}

	report += fmt.Sprintf("\nIssues: %d\n", len(result.Issues))
	for i, issue := range result.Issues {
		report += fmt.Sprintf("\n%d. [%s] %s\n   %s\n", i+1, issue.Severity, issue.Description, issue.Details)
	}

	return report
}