package relay

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"transfer/internal/wire"
)

// Version is the relay's build label, reported at startup and in -v.
const Version = "1.3.0"

// Start brings the relay up and returns as soon as it is listening, so an
// embedding program (STRS.exe) can host it without a second window.
func Start(cfg Config, lg *log.Logger) (*Server, error) {
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}
	if err := os.MkdirAll(cfg.State, 0o700); err != nil {
		return nil, fmt.Errorf("state dir %s: %w", cfg.State, err)
	}

	h := &hub{
		cfg:      cfg,
		sess:     map[string]*session{},
		failures: map[string]*failure{},
		log:      lg,
	}
	if err := h.loadOrMakeCert(); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*h.cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		if portInUse(cfg.Listen) {
			return nil, fmt.Errorf("a relay is already running on %s", portOf(cfg.Listen))
		}
		return nil, fmt.Errorf("cannot listen on %s: %w", cfg.Listen, err)
	}

	port := portOf(cfg.Listen)
	if !cfg.NoFirewall {
		configureFirewall(port, cfg.State, false, lg.Printf)
	}
	var disco net.PacketConn
	if !cfg.NoDiscovery {
		if tcpPort, perr := strconv.Atoi(port); perr == nil {
			if d, derr := startResponder(DiscoveryPort, tcpPort, h.pin); derr != nil {
				lg.Printf("discovery: not answering searches on your network (%v)", derr)
			} else {
				disco = d
				lg.Printf("discovery: answering searches on UDP %d, so people on your network need only the password", DiscoveryPort)
			}
		}
	}
	advertise := cfg.Advertise
	var undo func()
	if advertise == "" {
		advertise, undo = h.resolveAdvertise(port)
	}
	cfg.Advertise = advertise
	h.cfg = cfg

	lg.Printf("STRS relay %s listening on %s", Version, cfg.Listen)
	lg.Printf("cert pin %s", h.pin)
	lg.Printf("hand this to friends: %s", advertise)
	lg.Printf("chunk %s | streams/session %d | ttl %s | max sessions %d",
		wire.Human(cfg.Chunk), cfg.Streams, cfg.TTL, cfg.MaxSessions)

	s := &Server{cfg: cfg, hub: h, ln: ln, log: lg, undo: undo, disco: disco, done: make(chan struct{})}
	go h.janitor()
	go s.accept()
	return s, nil
}

// Server is a running relay.
type Server struct {
	cfg   Config
	hub   *hub
	ln    net.Listener
	log   *log.Logger
	undo  func()
	disco net.PacketConn
	done  chan struct{}

	mu     sync.Mutex
	closed bool
}

func (s *Server) accept() {
	defer close(s.done)
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.hub.serve(nc)
	}
}

// Advertise is the address friends should dial.
func (s *Server) Advertise() string { return s.cfg.Advertise }

// Pin is the certificate fingerprint clients pin against.
func (s *Server) Pin() string { return s.hub.pin }

// Close stops listening, removes any router mapping and waits for the accept
// loop to finish.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	_ = s.ln.Close()
	if s.disco != nil {
		_ = s.disco.Close()
	}
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
	}
	if s.undo != nil {
		s.undo()
	}
}

// Served is how many bytes the relay has actually delivered to receivers, which
// is the honest throughput figure (the sender's own count runs ahead by
// whatever sits in socket buffers).
func (s *Server) Served() int64 {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	var total int64
	for _, sess := range s.hub.sess {
		total += atomic.LoadInt64(&sess.served)
	}
	return total
}
