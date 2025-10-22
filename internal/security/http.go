package security

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// SecureHTTPClientConfig holds configuration for creating secure HTTP clients
type SecureHTTPClientConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool   // Allow self-signed certificates (routers often have them)
	MaxResponseSize    int64  // Maximum response body size in bytes
	MinTLSVersion      uint16 // Minimum TLS version (default: TLS 1.2)
}

// DefaultSecureClientConfig returns a secure default configuration
func DefaultSecureClientConfig() SecureHTTPClientConfig {
	return SecureHTTPClientConfig{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true, // Routers typically have self-signed certs
		MaxResponseSize:    10 * 1024 * 1024, // 10MB
		MinTLSVersion:      tls.VersionTLS12,
	}
}

// StrictSecureClientConfig returns a strict security configuration
// Use this when connecting to trusted external services
func StrictSecureClientConfig() SecureHTTPClientConfig {
	return SecureHTTPClientConfig{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: false, // Require valid certificates
		MaxResponseSize:    1 * 1024 * 1024, // 1MB
		MinTLSVersion:      tls.VersionTLS12,
	}
}

// NewSecureHTTPClient creates an HTTP client with security best practices
func NewSecureHTTPClient(config SecureHTTPClientConfig) *http.Client {
	return &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.InsecureSkipVerify,
				MinVersion:         config.MinTLSVersion,
				// Disable older, insecure cipher suites
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				},
			},
			// Add reasonable timeouts for all phases
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Limit idle connections to prevent resource exhaustion
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// LimitedReadAll reads response body with size limit to prevent DoS
func LimitedReadAll(body io.ReadCloser, maxSize int64) ([]byte, error) {
	defer body.Close()
	limitedReader := io.LimitReader(body, maxSize)
	return io.ReadAll(limitedReader)
}

// SafeHTTPGet performs an HTTP GET with size limits
func SafeHTTPGet(client *http.Client, url string, maxResponseSize int64) (*http.Response, []byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}

	body, err := LimitedReadAll(resp.Body, maxResponseSize)
	if err != nil {
		return resp, nil, err
	}

	return resp, body, nil
}
