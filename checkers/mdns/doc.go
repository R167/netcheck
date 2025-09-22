// Package mdns provides multicast DNS (mDNS) service discovery functionality for netcheck.
//
// This checker discovers services advertising via mDNS/Bonjour on the local network.
// It can perform both basic detection and comprehensive service enumeration,
// identifying potential security risks from exposed services.
//
// The mdns checker is a router-based checker that requires router access
// and helps identify information disclosure risks from mDNS service advertisements.
package mdns
