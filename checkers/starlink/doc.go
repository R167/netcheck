// Package starlink provides Starlink Dishy detection and security assessment functionality for netcheck.
//
// This checker detects Starlink satellite internet terminals (Dishy) on the network
// and performs security assessments of their configuration and accessibility.
// It uses gRPC calls to gather device information, status, and configuration.
//
// The starlink checker is a router-based checker that requires router access
// and helps identify Starlink terminals and their security implications.
package starlink
