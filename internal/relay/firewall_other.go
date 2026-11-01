//go:build !windows

package relay

// Linux and macOS relays rely on the host firewall being open; there is no
// single permission model to prompt against, so these are no-ops.
func configureFirewall(port, stateDir string, interactive bool, logf func(string, ...any)) {}
func addFirewallRule(port string) error                                                    { return nil }
func writeFirewallMarker(stateDir, port string)                                            {}
