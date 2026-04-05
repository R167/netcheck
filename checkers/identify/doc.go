// Package identify implements a network host identification checker.
// It resolves IP addresses to MAC addresses via the ARP table, performs
// OUI vendor lookups, grabs HTTP headers and TCP banners to fingerprint
// remote devices on the local network.
package identify
