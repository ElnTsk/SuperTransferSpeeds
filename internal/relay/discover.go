package relay

// Finding a sender on the same network without typing its address.
//
// A relay answers a tiny UDP search on DiscoveryPort with the port it listens
// on and its certificate pin. A receiver broadcasts that search, collects the
// answers, and then tries the password against each relay it found. Only
// private-network addresses are answered or accepted, so this never reaches
// across the internet and cannot be used to bounce traffic at a stranger.
//
// The answer is not secret (it is the same address and pin the TCP port shows
// to anyone who connects), and a fake answer gains an attacker nothing: files
// are encrypted with a key made from the password, which the relay never sees.

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// DiscoveryPort is the UDP port a relay answers searches on.
const DiscoveryPort = 48443

const probeMagic = "STRS?1"

type announcement struct {
	App  string `json:"app"`
	V    int    `json:"v"`
	Port int    `json:"port"`
	Pin  string `json:"pin"`
}

// Found is a relay that answered a search.
type Found struct {
	Addr string // host:port to dial
	Pin  string // certificate pin to expect
}

// privateSource says whether an address belongs to a home or office network.
func privateSource(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// startResponder answers searches until the returned connection is closed.
func startResponder(udpPort, tcpPort int, pin string) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp4", net.JoinHostPort("", strconv.Itoa(udpPort)))
	if err != nil {
		return nil, err
	}
	reply, _ := json.Marshal(announcement{App: "STRS", V: 1, Port: tcpPort, Pin: pin})
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok || !privateSource(ua.IP) {
				continue
			}
			if strings.TrimSpace(string(buf[:n])) != probeMagic {
				continue
			}
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return pc, nil
}

// probeTargets is every place worth shouting at: the global broadcast, this
// machine, and the broadcast address of each connected network.
func probeTargets() []net.IP {
	targets := []net.IP{net.IPv4bcast, net.IPv4(127, 0, 0, 1)}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			mask := ipn.Mask
			if len(mask) == net.IPv6len {
				mask = mask[12:]
			}
			if ip4 == nil || len(mask) != 4 {
				continue
			}
			b := make(net.IP, 4)
			for i := range b {
				b[i] = ip4[i] | ^mask[i]
			}
			targets = append(targets, b)
		}
	}
	return targets
}

// Discover searches this network and returns every relay that answered within
// the wait. A sender on this same PC answers too.
func Discover(udpPort int, wait time.Duration) []Found {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil
	}
	defer pc.Close()

	for _, t := range probeTargets() {
		_, _ = pc.WriteTo([]byte(probeMagic), &net.UDPAddr{IP: t, Port: udpPort})
	}
	_ = pc.SetReadDeadline(time.Now().Add(wait))

	seen := map[string]bool{}
	var out []Found
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || !privateSource(ua.IP) {
			continue
		}
		var a announcement
		if json.Unmarshal(buf[:n], &a) != nil || a.App != "STRS" ||
			a.Port <= 0 || a.Port > 65535 || !strings.HasPrefix(a.Pin, "sha256/") {
			continue
		}
		key := a.Pin + "|" + strconv.Itoa(a.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Found{Addr: net.JoinHostPort(ua.IP.String(), strconv.Itoa(a.Port)), Pin: a.Pin})
	}
	return out
}
