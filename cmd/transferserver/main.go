// Command transferserver runs the relay standalone, for a machine that only
// hosts (a server, or a spare PC). STRS.exe can also host it inline.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"transfer/internal/relay"
	"transfer/internal/wire"
)

func main() {
	cfg, logPath, installPort := parseFlags()
	interactive := isTerminal()

	if installPort != "" {
		if err := relay.InstallFirewallRule(installPort, cfg.State); err != nil {
			fmt.Println("firewall:", err)
			os.Exit(1)
		}
		fmt.Printf("firewall: allowed inbound TCP %s\n", installPort)
		return
	}

	lg := log.New(os.Stdout, "relay ", log.LstdFlags)
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: log file %s: %v\n", logPath, err)
			os.Exit(1)
		}
		lg = log.New(io.MultiWriter(os.Stdout, f), "relay ", log.LstdFlags)
	}

	srv, err := relay.Start(cfg, lg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay: %v\n", err)
		pauseIf(interactive)
		os.Exit(1)
	}
	if interactive {
		lg.Printf("this window is the relay - keep it open, Ctrl+C stops it")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	lg.Printf("shutting down")
	srv.Close()
}

func parseFlags() (relay.Config, string, string) {
	var c relay.Config
	var logPath, installPort string
	flag.StringVar(&c.Listen, "listen", ":8443", "TLS listen address")
	flag.StringVar(&c.Advertise, "advertise", "", "host:port clients dial")
	flag.StringVar(&c.State, "state", defaultState(), "directory for the cert")
	flag.Int64Var(&c.Chunk, "chunk", wire.DefaultMib, "chunk size for medium and large files")
	flag.IntVar(&c.Streams, "streams", 16, "parallel data lanes allowed per session")
	flag.DurationVar(&c.TTL, "ttl", 24*time.Hour, "password lifetime")
	flag.IntVar(&c.MaxSessions, "max-sessions", 4, "concurrent live sessions")
	flag.IntVar(&c.PublicPort, "public-port", 0, "external port to forward (default: from config, else 8443)")
	flag.BoolVar(&c.NoUPnP, "no-upnp", false, "do not ask the router to forward a port")
	flag.BoolVar(&c.NoFirewall, "no-firewall", false, "do not touch the Windows Firewall")
	flag.StringVar(&installPort, "install-port", "", "internal: add the firewall rule for this port and exit")
	flag.StringVar(&logPath, "log", "", "also append the log to this file")
	flag.Parse()

	if c.Chunk <= 0 {
		c.Chunk = wire.DefaultMib
	}
	if c.Streams < 1 {
		c.Streams = 1
	}
	if c.MaxSessions < 1 {
		c.MaxSessions = 1
	}
	if c.TTL < time.Minute {
		c.TTL = time.Minute
	}
	if c.PublicPort == 0 {
		c.PublicPort = relay.SharedPublicPort()
	}
	return c, logPath, installPort
}

func defaultState() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "STRS", "relay")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".strs-relay")
	}
	return ".strs-relay"
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func pauseIf(interactive bool) {
	if !interactive {
		return
	}
	fmt.Print("\npress Enter to close this window")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()
}
