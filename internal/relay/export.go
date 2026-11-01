package relay

import "net"

// InstallFirewallRule adds the inbound allow rule and records it, for the
// elevated half of first-run setup. Needs administrator rights.
func InstallFirewallRule(port, stateDir string) error {
	if err := addFirewallRule(port); err != nil {
		return err
	}
	writeFirewallMarker(stateDir, port)
	return nil
}

// SharedPublicPort is the external port the client config already settled on.
func SharedPublicPort() int { return sharedPublicPort() }

// LANHost is this PC's preferred private IPv4 with the port, or "" when the
// machine has no non-loopback address.
func LANHost(port string) string {
	if ip := preferredIPv4(); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	return ""
}

// IsOwnIP reports whether host is an address assigned to this machine.
func IsOwnIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, a := range localIPv4s() {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}
