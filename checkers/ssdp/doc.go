// Package ssdp provides SSDP (Simple Service Discovery Protocol) service discovery functionality for netcheck.
//
// This checker performs comprehensive SSDP multicast discovery to identify network services
// including DLNA media servers, printers, IoT devices, and other UPnP-enabled services.
// It supports both IPv4 and IPv6 discovery and provides security assessment of exposed services.
//
// The ssdp checker is a router-based checker that discovers services on the local network
// and helps identify potentially exposed or vulnerable network devices.
package ssdp
