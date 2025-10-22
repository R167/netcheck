# Security Policy

## Supported Use Cases

Netcheck is designed for **authorized network security assessments only**. This tool is intended for:

- ✅ Auditing your own home network security
- ✅ Assessing networks you have explicit permission to test
- ✅ Educational purposes in controlled environments
- ✅ Security research on your own infrastructure

This tool is **NOT** intended for:

- ❌ Unauthorized network scanning
- ❌ Penetration testing without written authorization
- ❌ Reconnaissance of networks you don't own/control
- ❌ Any activity that violates applicable laws or regulations

## Legal Notice

**You are responsible for ensuring you have proper authorization before scanning any network.**

Unauthorized network scanning may be illegal in your jurisdiction and could result in:
- Criminal prosecution under computer fraud and abuse laws
- Civil liability for damages
- Network access restrictions or bans
- Violation of terms of service with your ISP

By using this tool, you acknowledge that:
1. You have authorization to scan the target network
2. You understand and accept the legal risks
3. You will not use this tool for malicious purposes
4. The authors are not responsible for misuse of this software

## Privacy Notice

### Data Collection

Netcheck:
- ✅ Performs local network scans
- ✅ Tests credentials locally (never transmitted to third parties)
- ✅ Outputs results to stdout only
- ❌ Does NOT send scan results to external servers
- ❌ Does NOT collect telemetry or analytics

### External Requests

The `--external` flag causes Netcheck to contact external services:
- `api.ipify.org` - External IP discovery
- `httpbin.org` - External IP verification
- `ifconfig.me` - External IP lookup
- `ip-api.com` - Geolocation information
- `ipapi.co` - ISP information

These services receive:
- Your public IP address
- Standard HTTP headers (User-Agent, etc.)

**Privacy Recommendation:** Do not use `--external` flag in sensitive environments.

## Security Features

### Input Validation

Netcheck includes security controls to prevent misuse:

1. **IP Address Validation** (v0.3.0+)
   - Only private IP ranges allowed (RFC 1918, RFC 4193)
   - Blocks public IP addresses
   - Prevents scanning of external networks

2. **Rate Limiting** (v0.3.0+)
   - Credential tests: Max 2 per second
   - Port scans: Configurable delays
   - Prevents triggering IDS/IPS alerts

3. **TLS Configuration** (v0.3.0+)
   - Minimum TLS 1.2
   - Strong cipher suites only
   - Certificate validation (configurable for routers)

4. **Response Size Limits**
   - XML responses: Limited to prevent XXE attacks
   - JSON responses: Limited to prevent DoS
   - HTTP bodies: Configurable maximum size

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in Netcheck, please report it responsibly.

### Reporting Process

1. **Do NOT** open a public GitHub issue
2. **Do NOT** disclose the vulnerability publicly
3. **Email** security details to: [Maintainer - see GitHub profile]

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Timeline:** Varies by severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### Vulnerability Disclosure Policy

- We will work with you to understand and address the issue
- We will credit you in the security advisory (unless you prefer anonymity)
- We will notify users once a fix is available
- We follow coordinated disclosure practices

## Security Best Practices for Users

### Before Running Netcheck

1. **Verify Authorization**
   - Confirm you own or have permission for the target network
   - Obtain written authorization for corporate networks
   - Check local laws regarding network scanning

2. **Review Scope**
   - Understand what each check does
   - Use specific flags instead of `--all` initially
   - Start with read-only checks (`--web`, `--ports`)

3. **Consider Network Impact**
   - Inform network administrators before scanning
   - Avoid scanning during business hours
   - Use `--timeout` to limit scan duration

### During Scanning

1. **Monitor Output**
   - Review discovered credentials immediately
   - Document security findings
   - Stop scan if unexpected results occur

2. **Protect Credentials**
   - Use `--show-passwords` flag cautiously
   - Avoid running in shared terminal sessions
   - Clear terminal history if sensitive data displayed

3. **Respect Rate Limits**
   - Don't bypass rate limiting controls
   - Allow adequate time between scans
   - Monitor for IDS/IPS alerts

### After Scanning

1. **Secure Results**
   - Don't share output containing credentials
   - Store findings securely
   - Follow data protection regulations

2. **Take Action**
   - Change default credentials immediately
   - Address critical security issues promptly
   - Document remediation steps

3. **Responsible Disclosure**
   - If you discover vulnerabilities in products, report to vendors
   - Follow coordinated disclosure practices
   - Don't exploit discovered vulnerabilities

## Known Limitations

### Security Limitations

1. **Passive Testing Only**
   - Netcheck does not exploit vulnerabilities
   - Does not attempt privilege escalation
   - Does not modify router configurations

2. **No Persistence**
   - Does not install backdoors
   - Does not maintain access
   - All operations are stateless

3. **Limited Scope**
   - Focuses on common misconfigurations
   - Does not perform deep packet inspection
   - Does not analyze firmware for vulnerabilities

### Technical Limitations

1. **Network Requirements**
   - Requires local network connectivity
   - May require elevated privileges for some checks (LLDP)
   - Firewall rules may block some tests

2. **Detection Avoidance**
   - Netcheck is NOT designed to evade detection
   - May trigger IDS/IPS alerts (intentionally)
   - Network administrators may detect scanning activity

3. **Accuracy**
   - Gateway discovery is heuristic-based
   - Vendor detection relies on pattern matching
   - False positives/negatives are possible

## Compliance Considerations

### Applicable Regulations

Users should consider:

- **Computer Fraud and Abuse Act (CFAA)** - US
- **Computer Misuse Act** - UK
- **GDPR** - EU (for credential handling)
- **HIPAA** - US Healthcare (for medical networks)
- **PCI-DSS** - Payment card networks
- **SOX** - Corporate governance (US)

### Industry Standards

Netcheck aligns with:

- **NIST Cybersecurity Framework** - Identify, Protect, Detect
- **OWASP** - Secure coding practices
- **CIS Controls** - Network security assessment
- **ISO 27001** - Information security management

## Security Update Policy

### Update Channels

- **GitHub Releases:** All security updates published
- **Security Advisories:** Critical vulnerabilities only
- **CHANGELOG.md:** Detailed security fix notes

### Update Recommendations

- ✅ Review CHANGELOG.md before updating
- ✅ Test updates in non-production environment first
- ✅ Subscribe to GitHub release notifications
- ✅ Join security mailing list (if available)

## Third-Party Dependencies

Netcheck uses the following third-party libraries:

- **hashicorp/mdns** - mDNS service discovery
- **Standard Go libraries** - Networking, HTTP, XML, JSON

### Dependency Security

- Dependencies are pinned to specific versions
- Run `go mod verify` to check integrity
- Use `govulncheck` for vulnerability scanning:
  ```bash
  go install golang.org/x/vuln/cmd/govulncheck@latest
  govulncheck ./...
  ```

## Contact

For security-related questions:
- **Email:** See GitHub profile for contact information
- **GitHub Issues:** For non-sensitive questions only
- **Discussions:** Community security best practices

---

**Last Updated:** 2025-10-22
**Version:** 0.3.0
