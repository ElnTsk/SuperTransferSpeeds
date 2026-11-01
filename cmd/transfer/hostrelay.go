package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"transfer/internal/relay"
	"transfer/internal/wire"
)

// maybeHostRelay starts an in-process relay when the configured server is this
// machine and nothing is listening yet. It returns nil when the relay is
// somebody else's or is already running.
func maybeHostRelay(addr string) (*relay.Server, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !(isLocalHost(host) || relay.IsOwnIP(host)) {
		return nil, nil
	}
	if probeTCP(addr, 300*time.Millisecond) {
		return nil, nil
	}

	// Same folder the standalone relay uses, so the certificate (and therefore
	// the pin friends were given) survives switching between the two.
	stateDir := relayStateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the relay state folder: %w", err)
	}
	logDir := filepath.Join(os.TempDir(), appName)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(logDir, "relay.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	// Startup lines go to the console too: the firewall and router setup is the
	// part a person needs to see happen.
	lg := log.New(io.MultiWriter(os.Stdout, lf), "relay ", log.LstdFlags)

	chunk := appCfg.Chunk
	if chunk <= 0 {
		chunk = wire.DefaultMib
	}
	cfg := relay.Config{
		Listen:      "0.0.0.0:" + port,
		State:       stateDir,
		Chunk:       chunk,
		Streams:     appCfg.Streams,
		TTL:         24 * time.Hour,
		MaxSessions: 4,
		PublicPort:  appCfg.PublicPort,
	}
	srv, err := relay.Start(cfg, lg)
	if err != nil {
		return nil, err
	}

	// Wait for the listener to answer before the client dials it.
	for i := 0; i < 40; i++ {
		if probeTCP(addr, 200*time.Millisecond) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !probeTCP(addr, 400*time.Millisecond) {
		srv.Close()
		return nil, fmt.Errorf("the built-in relay did not come up on %s", addr)
	}
	hostedRelay = srv
	return srv, nil
}

// relayStateDir mirrors the standalone relay's default so both share one cert.
func relayStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, appName, "relay")
	}
	return filepath.Join(os.TempDir(), appName, "relay")
}

// hostedRelay is the in-process relay for this run, so progress can report what
// it delivered rather than what was handed to it.
var hostedRelay *relay.Server

// localRelayAddr is where a sender hosts its own relay: the same port the
// standalone relay uses, on this PC's LAN address so what is shown and dialled
// is reachable from the network. Falls back to loopback with no network.
func localRelayAddr() string {
	if a := relay.LANHost("8443"); a != "" {
		return a
	}
	return "127.0.0.1:8443"
}
