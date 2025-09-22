// Package natpmp provides NAT Port Mapping Protocol (NAT-PMP) detection functionality for netcheck.
//
// This checker detects NAT-PMP services on routers, which allow applications to
// automatically create port mappings through the router's NAT. While useful for
// applications, it can pose security risks if not properly controlled.
//
// The natpmp checker is a router-based checker that requires router access
// and helps identify automatic port mapping capabilities.
package natpmp
