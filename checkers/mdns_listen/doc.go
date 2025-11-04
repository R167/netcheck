// Package mdns_listen implements passive mDNS query monitoring for network security assessment.
//
// This checker listens for mDNS queries on the network to identify:
// - Devices actively searching for services
// - Types of services being queried (both service patterns like "_http._tcp.local" and hostnames like "device.local")
// - Potential reconnaissance activity
//
// Unlike active mDNS discovery, this is a passive monitoring approach that captures
// mDNS queries sent by other devices on the network.
//
// Optional Re-Query Feature:
// When enabled via the ReQuery config option, the checker will actively query for
// the services it heard being queried during the listening phase. This discovers
// which devices are actually responding to those service queries, providing a
// complete picture of both:
// - Who is searching (passive listening)
// - What they're finding (active re-query)
package mdns_listen
