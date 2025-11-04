// Package mdns_listen implements passive mDNS query monitoring for network security assessment.
//
// This checker listens for mDNS queries on the network to identify:
// - Devices actively searching for services
// - Types of services being queried
// - Potential reconnaissance activity
//
// Unlike active mDNS discovery, this is a passive monitoring approach that captures
// mDNS queries sent by other devices on the network.
package mdns_listen
