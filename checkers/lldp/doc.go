// Package lldp provides Link Layer Discovery Protocol (LLDP) neighbor discovery functionality for netcheck.
//
// This checker discovers and analyzes LLDP neighbors on the local network.
// LLDP is used by network devices to advertise information about themselves
// to other devices on the network, including device capabilities, management
// addresses, and system descriptions.
//
// The lldp checker is a standalone checker that does not require router access
// and can reveal information about connected network infrastructure devices.
package lldp
