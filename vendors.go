package main

import "regexp"

// DefaultCred represents a set of default credentials for router authentication
type DefaultCred struct {
	Username string
	Password string
}

// Vendor patterns compiled at package level for efficiency
var (
	linksysPattern  = regexp.MustCompile(`(?i)linksys|smart\s*wi-fi`)
	netgearPattern  = regexp.MustCompile(`(?i)netgear|genie`)
	dlinkPattern    = regexp.MustCompile(`(?i)d-link|dir-\d+`)
	tplinkPattern   = regexp.MustCompile(`(?i)tp-link|tl-\w+`)
	asusPattern     = regexp.MustCompile(`(?i)asus|rt-\w+`)
	ciscoPattern    = regexp.MustCompile(`(?i)cisco|linksys`)
	belkinPattern   = regexp.MustCompile(`(?i)belkin|play max`)
	motorolaPattern = regexp.MustCompile(`(?i)motorola|surfboard`)
	xfinityPattern  = regexp.MustCompile(`(?i)xfinity|comcast|technicolor`)
	arrisPattern    = regexp.MustCompile(`(?i)arris|surfboard`)
	huaweiPattern   = regexp.MustCompile(`(?i)huawei|echolife`)
	ztePattern      = regexp.MustCompile(`(?i)zte`)
	actiontecPattern = regexp.MustCompile(`(?i)actiontec|verizon`)
	titlePattern    = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
)

// vendorPatterns maps vendor names to their compiled regex patterns
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

// defaultCredentials contains default username/password combinations for each vendor
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

// defaultPageIndicators contains strings that indicate a router is using default configuration
var defaultPageIndicators = []string{
	"welcome to your new router",
	"initial setup",
	"quick setup wizard",
	"router configuration",
	"default password",
	"change default password",
	"setup wizard",
}