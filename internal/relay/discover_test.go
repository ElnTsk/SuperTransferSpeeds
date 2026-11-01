package relay

import (
	"net"
	"testing"
	"time"
)

func TestPrivateSourceOnlyAcceptsLocalNetworks(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.55", "169.254.3.4"} {
		if !privateSource(net.ParseIP(s)) {
			t.Errorf("%s is a local address and should be accepted", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "83.105.10.174", "1.1.1.1", "172.32.0.1"} {
		if privateSource(net.ParseIP(s)) {
			t.Errorf("%s is a public address and must be ignored", s)
		}
	}
	if privateSource(nil) {
		t.Error("a missing address must be ignored")
	}
}

func TestDiscoverFindsAResponder(t *testing.T) {
	const udp = 48599
	pc, err := startResponder(udp, 8443, "sha256/testpin")
	if err != nil {
		t.Skipf("cannot bind UDP %d here: %v", udp, err)
	}
	defer pc.Close()

	found := Discover(udp, 700*time.Millisecond)
	if len(found) == 0 {
		t.Fatal("the responder was not found")
	}
	if found[0].Pin != "sha256/testpin" {
		t.Errorf("pin = %q", found[0].Pin)
	}
	_, port, _ := net.SplitHostPort(found[0].Addr)
	if port != "8443" {
		t.Errorf("port = %q, want 8443", port)
	}
}

func TestDiscoverIgnoresStrangersAndGarbage(t *testing.T) {
	const udp = 48598
	pc, err := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", "48598"))
	if err != nil {
		t.Skipf("cannot bind UDP %d here: %v", udp, err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// not JSON, wrong app, and a pin that is not a pin
			_, _ = pc.WriteTo([]byte("hello"), from)
			_, _ = pc.WriteTo([]byte(`{"app":"other","v":1,"port":1,"pin":"sha256/x"}`), from)
			_, _ = pc.WriteTo([]byte(`{"app":"STRS","v":1,"port":8443,"pin":"nope"}`), from)
		}
	}()
	if found := Discover(udp, 500*time.Millisecond); len(found) != 0 {
		t.Errorf("accepted bad answers: %+v", found)
	}
}
