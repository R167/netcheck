// Package external provides external IP address discovery and proxy detection functionality for netcheck.
//
// This checker discovers the external IPv4 and IPv6 addresses by querying multiple
// public IP detection services. It also provides geolocation information, ISP details,
// and can detect proxy/VPN/Tor usage.
//
// The external checker is a standalone checker that does not require router access
// and helps users understand their external network presence and connectivity.
package external
