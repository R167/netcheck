# Security Analysis Report - Netcheck

**Date:** 2025-10-22
**Analyzer:** Claude Code Security Review
**Scope:** Complete codebase security assessment

## Executive Summary

This security analysis identifies vulnerabilities and provides recommendations for improving the security posture of the Netcheck network security assessment tool. While the tool is designed for defensive security purposes, several improvements can enhance its robustness against malicious inputs and reduce potential risks to users running the tool.

**Overall Risk Level:** MEDIUM

The codebase is generally well-structured with good separation of concerns. However, several areas require attention to prevent potential security issues.

---

## Critical Findings

### 1. **Insecure Credential Testing Over HTTP**
**Severity:** CRITICAL
**Location:** `checkers/web/web.go:309-325`

**Issue:**
- Default credentials are transmitted over unencrypted HTTP connections
- Lines 218-219 attempt HTTP before HTTPS, exposing credentials on the wire
- Base64-encoded credentials in Authorization headers are trivially decoded if intercepted

**Code:**
```go
func testCredentials(client *http.Client, baseURL, username, password string) bool {
    auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
    req, err := http.NewRequest("GET", baseURL, nil)
    req.Header.Set("Authorization", "Basic "+auth)
    // Sent over HTTP if baseURL is http://...
```

**Impact:**
- Network eavesdroppers can intercept tested credentials
- Even though these are default credentials, transmitting them insecurely sets a bad precedent

**Recommendations:**
1. Prioritize HTTPS URLs over HTTP when testing credentials
2. Skip credential testing for HTTP-only endpoints with a warning
3. Add a `--allow-insecure-creds` flag to explicitly opt-in to HTTP credential testing
4. Display warnings when credentials are tested over HTTP

---

### 2. **Missing TLS Certificate Validation**
**Severity:** HIGH
**Location:** Multiple files (web.go, external.go, ssdp.go, api.go)

**Issue:**
- HTTP clients created without custom TLS configuration accept any certificate
- Self-signed or expired certificates are silently accepted
- Potential for MITM attacks when testing routers with invalid certificates

**Code:**
```go
client := &http.Client{
    Timeout: common.HTTPTimeout,
}
// No TLS configuration - accepts any certificate
```

**Impact:**
- Man-in-the-middle attacks possible on HTTPS connections
- Users may unknowingly accept compromised certificates

**Recommendations:**
1. Add explicit TLS configuration with proper certificate validation
2. For router testing, create a separate client with `InsecureSkipVerify` but warn users
3. Add a `--strict-tls` flag to enforce certificate validation
4. Log warnings when invalid certificates are encountered

**Example Fix:**
```go
client := &http.Client{
    Timeout: common.HTTPTimeout,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false, // Make configurable
            MinVersion:         tls.VersionTLS12,
        },
    },
}
```

---

## High-Severity Findings

### 3. **Missing Input Validation for IP Addresses**
**Severity:** HIGH
**Location:** `mcp_adapters.go:14-21, 41-48`

**Issue:**
- MCP adapter accepts `GatewayIP` without validation
- No checks for valid IP format, private IP ranges, or localhost
- Could be exploited to scan arbitrary network targets

**Code:**
```go
func adaptWebCheck(input *mcp.CheckToolInput) (*mcp.CheckToolOutput, error) {
    router := &common.RouterInfo{
        IP:     input.GatewayIP,  // No validation!
        Issues: []common.SecurityIssue{},
    }
```

**Impact:**
- Tool could be misused to scan external networks (port scanning, credential testing)
- Potential for abuse as a scanning proxy
- Liability issues if tool is used for unauthorized network scanning

**Recommendations:**
1. Add strict IP address validation:
   ```go
   func validateGatewayIP(ipStr string) error {
       ip := net.ParseIP(ipStr)
       if ip == nil {
           return fmt.Errorf("invalid IP address format: %s", ipStr)
       }

       // Only allow private IP ranges
       if !isPrivateIP(ip) {
           return fmt.Errorf("only private IP addresses allowed: %s", ipStr)
       }

       // Disallow localhost
       if ip.IsLoopback() {
           return fmt.Errorf("localhost not allowed: %s", ipStr)
       }

       return nil
   }

   func isPrivateIP(ip net.IP) bool {
       privateRanges := []string{
           "10.0.0.0/8",
           "172.16.0.0/12",
           "192.168.0.0/16",
           "fc00::/7", // IPv6 ULA
           "fe80::/10", // IPv6 link-local
       }

       for _, cidr := range privateRanges {
           _, network, _ := net.ParseCIDR(cidr)
           if network.Contains(ip) {
               return true
           }
       }
       return false
   }
   ```

2. Add prominent disclaimer in documentation about authorized use only
3. Consider logging all MCP scan requests to prevent abuse

---

### 4. **XML External Entity (XXE) Vulnerability Risk**
**Severity:** HIGH
**Location:** `checkers/ssdp/ssdp.go:273`

**Issue:**
- XML decoder created without explicitly disabling external entity processing
- Parses XML from untrusted network devices (UPnP/SSDP responses)
- Potential XXE attack if malicious device returns crafted XML

**Code:**
```go
func enrichServiceInfo(ssdp *common.SSDPService) {
    client := &http.Client{Timeout: 2 * time.Second}
    resp, err := client.Get(ssdp.Location)
    // ...
    var device common.UPnPDevice
    if err := xml.NewDecoder(resp.Body).Decode(&device); err == nil {
        // Parses untrusted XML
```

**Impact:**
- File disclosure on client machine
- Denial of service through entity expansion
- SSRF attacks via external entity loading

**Recommendations:**
1. Use a secure XML decoder configuration:
   ```go
   decoder := xml.NewDecoder(resp.Body)
   // Go's xml package doesn't support external entities by default,
   // but add size limits to prevent billion laughs attacks

   // Limit response body size
   limitedReader := io.LimitReader(resp.Body, 1024*1024) // 1MB max
   decoder := xml.NewDecoder(limitedReader)
   ```

2. Add input validation for XML structure
3. Implement timeout and size limits for all XML parsing

**Note:** Go's standard `encoding/xml` package does NOT process external entities by default, providing some protection. However, adding explicit size limits is still recommended.

---

### 5. **Insufficient Rate Limiting on Network Requests**
**Severity:** HIGH
**Location:** `checkers/web/web.go:277-307`, `checkers/ports/ports.go`

**Issue:**
- No rate limiting on credential testing attempts
- No delays between port scan attempts
- Could be detected as malicious scanning activity
- May trigger IDS/IPS alerts or account lockouts

**Code:**
```go
for _, cred := range creds {
    if testCredentials(client, baseURL, cred.Username, cred.Password) {
        // No delay between attempts
```

**Impact:**
- Tool traffic flagged as attack by security systems
- Account lockout on routers with brute-force protection
- Network administrator alerts

**Recommendations:**
1. Add configurable delay between credential tests:
   ```go
   const credTestDelay = 500 * time.Millisecond

   for _, cred := range creds {
       time.Sleep(credTestDelay)
       if testCredentials(client, baseURL, cred.Username, cred.Password) {
   ```

2. Add `--rate-limit` flag to control scan speed
3. Add exponential backoff for failed attempts
4. Limit total number of credential test attempts per vendor

---

## Medium-Severity Findings

### 6. **Information Disclosure in Output**
**Severity:** MEDIUM
**Location:** `checkers/web/web.go:301`, `mcp_adapters.go:82`

**Issue:**
- Displays working credentials in plaintext to stdout
- MCP output includes full credential details
- Sensitive information may be logged or visible over shoulder-surfing

**Code:**
```go
out.Error("🚨 Default credentials work: %s/%s", cred.Username, cred.Password)

// MCP output
report += fmt.Sprintf("\n%d. [%s] %s\n   %s\n", i+1, issue.Severity, issue.Description, issue.Details)
// issue.Details contains: "Username: 'admin', Password: 'password'"
```

**Impact:**
- Credentials exposed in terminal history
- Sensitive data in logs or screenshots
- Compliance issues (PCI-DSS, etc.)

**Recommendations:**
1. Redact passwords by default:
   ```go
   out.Error("🚨 Default credentials work: %s/[REDACTED]", cred.Username)
   out.Info("ℹ️  Run with --show-passwords to display passwords")
   ```

2. Add `--show-passwords` flag for explicit opt-in
3. Add `--json-output` flag for machine-readable output without display
4. Consider masking passwords in MCP output or providing a redacted mode

---

### 7. **Unreliable Gateway Discovery**
**Severity:** MEDIUM
**Location:** `internal/runner/gateway.go:16-33`

**Issue:**
- Assumes gateway is always .1 on the local subnet
- No validation that discovered address is actually a gateway
- Fails on networks with non-standard gateway addresses

**Code:**
```go
func DiscoverGateway() string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    // ...
    parts[3] = "1"  // Assumes .1 is gateway
    return strings.Join(parts, ".")
}
```

**Impact:**
- Tests run against wrong host
- False positives/negatives in security checks
- Potential scanning of unintended targets

**Recommendations:**
1. Parse system routing table for accurate gateway:
   ```go
   // On Linux: parse output of "ip route show default"
   // On macOS: parse output of "route -n get default"
   // On Windows: parse output of "route print"
   ```

2. Validate that discovered IP responds as a gateway:
   ```go
   func validateGateway(ip string) bool {
       // Try to connect to common router ports
       conn, err := net.DialTimeout("tcp", ip+":80", 2*time.Second)
       if err == nil {
           conn.Close()
           return true
       }
       return false
   }
   ```

3. Allow user to override gateway with `--gateway` flag
4. Display discovered gateway and ask for confirmation in interactive mode

---

### 8. **Command Injection Risk Mitigation Needed**
**Severity:** MEDIUM
**Location:** `checkers/device/device.go`, `checkers/routes/routes.go`

**Issue:**
- Multiple `exec.Command` calls with fixed arguments (currently safe)
- No user input interpolation (good!)
- But lacks explicit documentation of security assumptions

**Code:**
```go
cmd := exec.Command("cat", "/var/lib/dhcp/dhclient.leases")
cmd := exec.Command("route", "-n", "get", "default")
cmd := exec.Command("ip", "route", "show", "default")
```

**Current Status:** **NOT VULNERABLE** - Arguments are hardcoded

**Concern:**
- Future developers might add user input without proper sanitization
- No code review checklist ensures arguments remain safe

**Recommendations:**
1. Add security documentation comments:
   ```go
   // SECURITY: All arguments are hardcoded constants. Do NOT add user input
   // to exec.Command arguments without proper validation and sanitization.
   cmd := exec.Command("route", "-n", "get", "default")
   ```

2. Create a wrapper function for safe command execution:
   ```go
   // safeExec executes a command with validated arguments only
   func safeExec(allowedCommands map[string][]string, cmdName string) ([]byte, error) {
       args, ok := allowedCommands[cmdName]
       if !ok {
           return nil, fmt.Errorf("command not allowed: %s", cmdName)
       }
       return exec.Command(cmdName, args...).Output()
   }
   ```

3. Add static analysis checks (golangci-lint with gosec) to CI/CD

---

### 9. **Unrestricted External HTTP Requests**
**Severity:** MEDIUM
**Location:** `checkers/external/external.go:157-309`

**Issue:**
- Makes HTTP requests to hardcoded external services
- No option to disable external requests
- Potential privacy concerns (IP address sent to third parties)
- Network administrator may block or monitor these requests

**Code:**
```go
services := []struct {
    name string
    url  string
}{
    {"ipify", "https://api.ipify.org"},
    {"httpbin", "https://httpbin.org/ip"},
    {"ifconfig.me", "https://ifconfig.me/ip"},
    // ...
}
```

**Impact:**
- User's public IP sent to third-party services
- Privacy concerns for sensitive environments
- May violate corporate security policies
- Dependency on external services

**Recommendations:**
1. Add privacy warning when external checker runs:
   ```go
   fmt.Println("⚠️  This check will contact external services to determine your public IP address:")
   fmt.Println("   • api.ipify.org")
   fmt.Println("   • httpbin.org")
   fmt.Println("   Continue? (y/N): ")
   ```

2. Add `--no-external-requests` flag to disable all external calls
3. Document privacy implications in README
4. Consider adding option for users to specify their own IP lookup service

---

### 10. **JSON Parsing from Untrusted Sources**
**Severity:** MEDIUM
**Location:** `checkers/external/external.go:239-246, 300`

**Issue:**
- Parses JSON responses from external services without size limits
- No validation of response structure
- Potential DoS through large JSON payloads

**Code:**
```go
var jsonResp struct {
    Origin string `json:"origin"`
}
if err := json.Unmarshal(body, &jsonResp); err == nil {
    result = jsonResp.Origin
}
```

**Impact:**
- Memory exhaustion from large responses
- Denial of service
- Potential slowloris-style attacks

**Recommendations:**
1. Add response size limits:
   ```go
   // In queryIPService and getGeoLocationInfo
   limitedBody := io.LimitReader(resp.Body, 1024*100) // 100KB max
   body, err := io.ReadAll(limitedBody)
   ```

2. Validate JSON structure before full parsing
3. Add timeouts to all HTTP requests (already implemented - good!)
4. Consider using streaming JSON decoder for large responses

---

## Low-Severity Findings

### 11. **Hardcoded Credentials in Source Code**
**Severity:** LOW
**Location:** `checkers/web/web.go:60-128`

**Issue:**
- Default credentials stored as plaintext in source code
- Credentials are public knowledge (default router passwords)
- Still a code smell and could enable credential stuffing

**Current Status:** **ACCEPTABLE** - These are publicly known defaults

**Note:** While storing these credentials is necessary for the tool's functionality, consider:
1. Moving credentials to external JSON file for easier updates
2. Adding ability to load custom credential lists
3. Downloading latest credential database from secure source

**Recommendations:**
1. Add comment explaining why credentials are hardcoded:
   ```go
   // SECURITY NOTE: These are publicly documented default credentials
   // used by router manufacturers. They are not secrets and are
   // widely available in security databases.
   var defaultCredentials = map[string][]DefaultCred{
   ```

2. Consider external credential database:
   ```go
   // Load from DefaultCreds.com API or similar
   func loadCredentialDatabase() error {
       // Fetch latest default credentials
   }
   ```

---

### 12. **Verbose Error Messages**
**Severity:** LOW
**Location:** Multiple locations

**Issue:**
- Error messages may leak internal implementation details
- Stack traces could expose file paths and internal structure

**Impact:**
- Information disclosure about internal workings
- Fingerprinting attack surface

**Recommendations:**
1. Use generic error messages for external-facing errors
2. Add `--debug` flag for verbose error output
3. Log detailed errors to file instead of stdout

---

### 13. **UDP Buffer Size**
**Severity:** LOW
**Location:** `checkers/ssdp/ssdp.go:204`

**Issue:**
- Fixed 4096-byte buffer for UDP responses
- No protection against oversized responses

**Code:**
```go
buffer := make([]byte, 4096)
```

**Impact:**
- Potential memory issues with fragmented UDP packets
- Truncated responses if larger than 4KB

**Recommendations:**
1. Document maximum expected response size
2. Add warning if response is truncated
3. Consider dynamic buffer sizing

---

### 14. **Missing Context Propagation**
**Severity:** LOW
**Location:** Multiple checker implementations

**Issue:**
- Main context with timeout not propagated to all checkers
- Some operations may continue after global timeout
- HTTP clients don't use request contexts

**Impact:**
- Operations continue after timeout
- Resource leaks from abandoned operations

**Recommendations:**
1. Add context parameter to all checker functions:
   ```go
   func (c *WebChecker) Run(ctx context.Context, config checker.CheckerConfig, ...) {
   ```

2. Use context-aware HTTP requests:
   ```go
   req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
   ```

3. Check context cancellation in loops:
   ```go
   select {
   case <-ctx.Done():
       return ctx.Err()
   default:
       // Continue processing
   }
   ```

---

## Additional Security Recommendations

### 15. **Dependency Security**

**Current Status:** Not Assessed
**Recommendation:**
1. Run `go mod verify` to check dependencies
2. Use `govulncheck` to scan for known vulnerabilities:
   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   govulncheck ./...
   ```
3. Add Dependabot or similar to monitor dependencies
4. Regular security updates for third-party libraries

---

### 16. **Code Security Scanning**

**Recommendation:**
1. Integrate gosec into CI/CD pipeline:
   ```bash
   go install github.com/securego/gosec/v2/cmd/gosec@latest
   gosec -exclude=G104 ./...  # Exclude unchecked errors if desired
   ```

2. Add staticcheck:
   ```bash
   go install honnef.co/go/tools/cmd/staticcheck@latest
   staticcheck ./...
   ```

3. Enable Go vet in CI:
   ```bash
   go vet ./...
   ```

---

### 17. **Privilege Separation**

**Current Status:** Runs with user privileges
**Consideration:**
- Some checks (LLDP, raw sockets) may require elevated privileges
- Document minimum required privileges for each check
- Add privilege checking before operations that require elevation
- Warn users when running as root

**Recommendation:**
```go
func requiresRoot() bool {
    return os.Geteuid() == 0
}

func checkPrivileges() {
    if requiresRoot() {
        fmt.Println("⚠️  Running as root - consider using regular user privileges")
    }
}
```

---

### 18. **Security Documentation**

**Recommendation:**
Create `SECURITY.md` with:
1. Supported use cases (authorized network scanning only)
2. Security reporting process
3. Known limitations
4. Privacy implications
5. Network administrator notification requirements

**Example Template:**
```markdown
# Security Policy

## Supported Use

This tool is intended for:
- Authorized network security assessments
- Home network security audits
- Educational purposes

This tool is NOT intended for:
- Unauthorized network scanning
- Penetration testing without permission
- Malicious reconnaissance

## Reporting Security Issues

Please report security vulnerabilities to: [contact]

## Privacy Notice

This tool:
- Sends requests to your local network gateway
- May contact external IP lookup services
- Does not transmit scan results externally
- Logs all operations to stdout

## Legal Notice

Users are responsible for ensuring they have authorization
to scan target networks. Unauthorized network scanning may
be illegal in your jurisdiction.
```

---

## Severity Classification

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 1 | Insecure credential transmission |
| HIGH | 4 | Input validation, TLS, XXE, rate limiting |
| MEDIUM | 5 | Information disclosure, gateway discovery, external requests |
| LOW | 4 | Hardcoded credentials, error messages, buffer sizes, contexts |

---

## Prioritized Remediation Roadmap

### Phase 1: Critical Fixes (Immediate)
1. Add TLS configuration with proper certificate handling
2. Prioritize HTTPS over HTTP for credential testing
3. Implement IP address validation for MCP inputs
4. Add rate limiting to credential tests

### Phase 2: High-Priority Fixes (1-2 weeks)
1. Add XML response size limits
2. Improve gateway discovery accuracy
3. Add privacy warnings for external requests
4. Implement JSON response size limits

### Phase 3: Medium-Priority Improvements (1 month)
1. Add credential redaction with opt-in display
2. Create security documentation (SECURITY.md)
3. Add command execution security comments
4. Implement context propagation

### Phase 4: Long-Term Improvements (Ongoing)
1. Set up dependency scanning
2. Integrate security linters (gosec, staticcheck)
3. Add external credential database support
4. Implement privilege checking

---

## Code Quality Observations

### Strengths:
1. **Good separation of concerns** - Modular checker architecture
2. **No user input in exec.Command** - Commands use fixed arguments
3. **Timeout handling** - Most network operations have timeouts
4. **Error handling** - Errors are checked and handled appropriately
5. **Clean interfaces** - Well-defined checker interface pattern

### Areas for Improvement:
1. Missing input validation on external inputs
2. Lack of rate limiting on network operations
3. No security-focused code review checklist
4. Limited security documentation
5. No automated security scanning in CI/CD

---

## Testing Recommendations

### Security Test Cases to Add:

1. **Input Validation Tests:**
   ```go
   func TestValidateIP_RejectPublicIPs(t *testing.T) {
       publicIPs := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
       for _, ip := range publicIPs {
           err := validateGatewayIP(ip)
           assert.Error(t, err)
       }
   }
   ```

2. **Rate Limiting Tests:**
   ```go
   func TestCredentialTesting_RateLimited(t *testing.T) {
       start := time.Now()
       // Test credentials
       duration := time.Since(start)
       assert.Greater(t, duration, expectedMinimumDuration)
   }
   ```

3. **XML Size Limit Tests:**
   ```go
   func TestXMLParsing_SizeLimits(t *testing.T) {
       largeXML := strings.Repeat("<tag>data</tag>", 1000000)
       // Should fail or timeout
   }
   ```

4. **TLS Certificate Tests:**
   ```go
   func TestHTTPClient_RejectsInvalidCerts(t *testing.T) {
       // Test that invalid certs are properly rejected
   }
   ```

---

## Compliance Considerations

### OWASP Top 10 Coverage:

1. **A01:2021 - Broken Access Control** ✅ ADDRESSED
   - Recommendation: Add IP validation to prevent unauthorized scanning

2. **A02:2021 - Cryptographic Failures** ⚠️ PARTIAL
   - Issue: TLS not properly configured
   - Recommendation: Implement proper TLS validation

3. **A03:2021 - Injection** ✅ SAFE
   - No SQL injection (no database)
   - No command injection (fixed arguments)
   - XML injection mitigated (Go's xml parser safe by default)

4. **A04:2021 - Insecure Design** ⚠️ NEEDS ATTENTION
   - Issue: Credential transmission over HTTP
   - Recommendation: Enforce HTTPS for sensitive operations

5. **A05:2021 - Security Misconfiguration** ⚠️ NEEDS ATTENTION
   - Issue: No default security headers, no TLS config
   - Recommendation: Add secure defaults

6. **A07:2021 - Identification and Authentication Failures** N/A
   - Tool doesn't implement authentication

7. **A08:2021 - Software and Data Integrity Failures** ⚠️ NEEDS ATTENTION
   - Recommendation: Add dependency verification

8. **A09:2021 - Security Logging and Monitoring Failures** ⚠️ MINIMAL
   - Recommendation: Add security event logging

9. **A10:2021 - Server-Side Request Forgery (SSRF)** ⚠️ VULNERABLE
   - Issue: No IP validation allows scanning arbitrary IPs
   - Recommendation: Implement IP allowlist (private ranges only)

---

## Conclusion

The Netcheck tool is well-architected with good code organization and error handling. The primary security concerns revolve around:

1. **Network security** - Missing TLS validation and insecure credential transmission
2. **Input validation** - Lack of IP address validation in MCP mode
3. **Privacy** - External requests without user consent
4. **Information disclosure** - Verbose credential display

These issues are manageable and can be addressed through the phased remediation approach outlined above. The tool's core design is sound, and with the recommended security enhancements, it will provide a robust and secure network assessment capability.

**Recommended Next Steps:**
1. Implement Phase 1 critical fixes immediately
2. Add security documentation (SECURITY.md)
3. Set up automated security scanning in CI/CD
4. Conduct regular security reviews as features are added

---

## Contact

For questions about this security analysis or to report additional findings, please contact the development team.
