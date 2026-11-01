// Command supertransfer-relay is the relay and token authority for SuperTransfer
// tool. It never writes file bytes to disk: bytes move sender lane -> relay ->
// receiver lane and are gone, which is what lets files over 100 GB cross a box
// with 29 GB free.
package relay

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"transfer/internal/upnp"
	"transfer/internal/wire"
)

const (
	relayVersion = "1.4.7"

	helloTimeout = 15 * time.Second
	controlIdle  = 5 * time.Minute
	laneWait     = 60 * time.Second
)

type Config struct {
	Listen      string
	Advertise   string
	State       string
	Chunk       int64
	Streams     int
	TTL         time.Duration
	MaxSessions int
	PublicPort  int
	NoUPnP      bool
	NoFirewall  bool
	InstallPort string
}

type hub struct {
	cfg  Config
	pin  string
	cert *tls.Certificate

	mu   sync.Mutex
	sess map[string]*session

	fmu      sync.Mutex
	failures map[string]*failure

	log *log.Logger
}

type failure struct {
	count int
	until time.Time
}

const (
	maxFailures   = 10
	failureWindow = 10 * time.Minute
)

// lane is one sender data connection, idle in the pool or owned by a worker.
type lane struct {
	c    *wire.Conn
	buf  []byte
	quit chan struct{}
	once sync.Once
}

func (l *lane) stop() {
	l.once.Do(func() {
		close(l.quit)
		_ = l.c.Close()
	})
}

type session struct {
	h       *hub
	key     string // sha256 of the shared password, never the password itself
	id      string // short label for logs
	created time.Time
	expires time.Time
	doneCh  chan struct{}

	mu       sync.Mutex
	root     string
	files    map[string]wire.File
	claimed  bool
	recvName string
	sender   *wire.Conn
	lanes    map[*lane]struct{}
	idle     chan *lane
	workers  map[*wire.Conn]struct{}
	closed   bool
	served   int64
}

// isTerminal tells a double-clicked run apart from one driven by flags or a
// service manager, which decides whether we may pause or ask questions.

// lanHost is the address a machine on the same network should dial.
func lanHost(port string) string {
	if ip := preferredIPv4(); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// preferredIPv4 picks the address a nearby machine would actually reach: real
// private LAN ranges first, so virtual adapters (Oculus, VPN, Radmin) do not
// win by being enumerated first.
func preferredIPv4() net.IP {
	var best net.IP
	bestRank := 100
	for _, ip := range localIPv4s() {
		rank := 3
		switch {
		case ip[0] == 192 && ip[1] == 168:
			rank = 0
		case ip[0] == 10:
			rank = 1
		case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
			rank = 2
		case ip[0] == 169 && ip[1] == 254:
			rank = 90
		}
		if rank < bestRank {
			best, bestRank = ip, rank
		}
	}
	return best
}

// resolveAdvertise works out what friends should dial: ask the router for a
// forwarded port, and fall back to the LAN address when that is not possible.
// The returned func removes the rule again on shutdown.
func (h *hub) resolveAdvertise(port string) (string, func()) {
	lan := lanHost(port)
	if h.cfg.NoUPnP {
		return lan, nil
	}
	r, err := upnp.Discover()
	if err != nil {
		h.log.Printf("router: %v", err)
		return lan, nil
	}
	pub, err := r.ExternalIP()
	if err != nil {
		h.log.Printf("router: %v", err)
		return lan, nil
	}
	internal, err := strconv.Atoi(port)
	if err != nil {
		return lan, nil
	}

	explicit := h.cfg.PublicPort > 0
	candidates := []int{8443, 9443, 9444, 9445, 10443}
	if explicit {
		candidates = []int{h.cfg.PublicPort}
	}
	for _, ext := range candidates {
		if err := r.AddMapping(ext, internal, "STRS"); err == nil {
			h.log.Printf("router: forwarding TCP %d to this PC", ext)
			if ext != 8443 {
				h.log.Printf("router: public port is %d (8443 was taken or blocked)", ext)
			}
			return net.JoinHostPort(pub, strconv.Itoa(ext)), func() {
				_ = r.DeleteMapping(ext)
			}
		} else if explicit {
			h.log.Printf("router: could not add TCP %d (%v) - assuming a rule already forwards it", ext, err)
			return net.JoinHostPort(pub, strconv.Itoa(ext)), nil
		} else {
			h.log.Printf("router: TCP %d not available (%v)", ext, err)
		}
	}
	h.log.Printf("router: no free port to forward, friends on your network are unaffected")
	return lan, nil
}

// portOf is the port half of a listen address, for the guidance lines.
func portOf(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	return "8443"
}

// pauseIf holds the console open for a double-clicked relay, so a port clash or
// a bad state dir is readable instead of a window that blinks and vanishes.

// localIPv4s lists this host's usable IPv4 addresses.
func localIPv4s() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() {
			continue
		}
		if ip := ipn.IP.To4(); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// --- connection dispatch --------------------------------------------------

func (h *hub) serve(nc net.Conn) {
	c := wire.Wrap(nc)
	defer func() {
		if r := recover(); r != nil {
			h.log.Printf("panic from %s: %v", c.RemoteAddr(), r)
		}
		_ = c.Close()
	}()

	_ = c.SetDeadline(time.Now().Add(helloTimeout))
	m, err := c.Recv()
	if err != nil {
		return
	}
	if m.T != "hello" || m.V != wire.ProtoV {
		_ = c.Send(wire.ErrMsg("proto", fmt.Sprintf("send hello with v=%d", wire.ProtoV)))
		return
	}

	switch m.Role {
	case "sender":
		h.handleSender(c, m)
	case "lane":
		h.handleLane(c, m)
	case "receiver":
		h.handleReceiver(c, m)
	case "worker":
		h.handleWorker(c, m)
	default:
		_ = c.Send(wire.ErrMsg("role", "unknown role "+m.Role))
	}
}

// lookup resolves a shared password and enforces a per-address guess limit,
// because a relay with a port forward is reachable by everybody.
func (h *hub) lookup(password, remote string) (*session, error) {
	key := credKey(password)
	ip, _, _ := net.SplitHostPort(remote)
	if ip == "" {
		ip = remote
	}

	h.fmu.Lock()
	f := h.failures[ip]
	blocked := f != nil && f.count >= maxFailures && time.Now().Before(f.until)
	wait := time.Duration(0)
	if blocked {
		wait = time.Until(f.until).Round(time.Second)
	}
	h.fmu.Unlock()
	if blocked {
		return nil, fmt.Errorf("rate_limited: too many wrong passwords from this address, try again in %s", wait)
	}

	s := h.get(key)
	if s == nil {
		h.noteFailure(ip)
		return nil, fmt.Errorf("bad_password: password not recognised")
	}
	if time.Now().After(s.expires) {
		h.noteFailure(ip)
		return nil, fmt.Errorf("expired: this session is past its %s window", h.cfg.TTL)
	}
	if s.isClosed() {
		h.noteFailure(ip)
		return nil, fmt.Errorf("gone: the sender has disconnected")
	}

	h.fmu.Lock()
	delete(h.failures, ip)
	h.fmu.Unlock()
	return s, nil
}

// minPasswordLen keeps a public relay from being opened with "1234".
const minPasswordLen = 8

// credKey is what the hub stores and compares: the password never sits in
// memory or in a log line.
func credKey(password string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(password)))
	return hex.EncodeToString(sum[:])
}

func (h *hub) noteFailure(ip string) {
	h.fmu.Lock()
	defer h.fmu.Unlock()
	f := h.failures[ip]
	if f == nil {
		if len(h.failures) > 4096 {
			h.failures = map[string]*failure{}
		}
		f = &failure{}
		h.failures[ip] = f
	}
	f.count++
	f.until = time.Now().Add(failureWindow)
}

func (h *hub) get(tok string) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sess[tok]
}

func (h *hub) put(s *session) {
	h.mu.Lock()
	h.sess[s.key] = s
	h.mu.Unlock()
}

func (h *hub) forget(tok string) {
	h.mu.Lock()
	delete(h.sess, tok)
	h.mu.Unlock()
}

// --- sender ---------------------------------------------------------------
func newGeneratedPassword(h *hub) (string, error) {
	for attempts := 0; attempts < 8; attempts++ {
		p, err := wire.NewToken(16)
		if err != nil {
			return "", err
		}
		if h.get(credKey(p)) == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("could not allocate a free password")
}

func (h *hub) handleSender(c *wire.Conn, hello wire.Msg) {
	h.mu.Lock()
	live := len(h.sess)
	h.mu.Unlock()
	if live >= h.cfg.MaxSessions {
		_ = c.Send(wire.ErrMsg("busy", fmt.Sprintf("%d sessions already live on this relay", live)))
		return
	}

	// The sender proposes the shared password; with none, one is generated so
	// a bare run still works.
	password := strings.TrimSpace(hello.Token)
	if password == "" {
		var err error
		password, err = newGeneratedPassword(h)
		if err != nil {
			_ = c.Send(wire.ErrMsg("rand", err.Error()))
			return
		}
	}
	if len([]rune(password)) < minPasswordLen {
		_ = c.Send(wire.ErrMsg("password_short", fmt.Sprintf("use a password of at least %d characters", minPasswordLen)))
		return
	}
	key := credKey(password)
	if live := h.get(key); live != nil && !live.isClosed() {
		_ = c.Send(wire.ErrMsg("in_use", "that password is already serving a transfer - pick another"))
		return
	}

	idTag, err := wire.NewToken(16)
	if err != nil {
		_ = c.Send(wire.ErrMsg("rand", err.Error()))
		return
	}
	name := orName(hello.Name, c.RemoteAddr())
	s := &session{
		h:       h,
		key:     key,
		id:      strings.Split(idTag, "-")[0],
		created: time.Now(),
		expires: time.Now().Add(h.cfg.TTL),
		doneCh:  make(chan struct{}),
		files:   map[string]wire.File{},
		lanes:   map[*lane]struct{}{},
		workers: map[*wire.Conn]struct{}{},
		idle:    make(chan *lane, h.cfg.Streams),
		sender:  c,
	}
	h.put(s)
	h.log.Printf("%s session open from %s with a shared password, expires %s", s.id, name, s.expires.Format("2006-01-02 15:04"))

	err = func() error {
		if err := c.Send(wire.Msg{
			T:        "token",
			Token:    password,
			Endpoint: h.cfg.Advertise,
			Pin:      h.pin,
			Expires:  s.expires.Unix(),
			Streams:  h.cfg.Streams,
			Chunk:    h.cfg.Chunk,
		}); err != nil {
			return err
		}

		var staged []wire.File
		for {
			_ = c.SetDeadline(time.Now().Add(controlIdle))
			m, err := c.Recv()
			if err != nil {
				return err
			}
			switch m.T {
			case "manifest":
				if m.Index == 0 {
					staged = nil
				}
				staged = append(staged, m.Files...)
				if !m.Done {
					continue
				}
				if err := s.setManifest(m.Root, staged); err != nil {
					return err
				}
				_ = c.Send(wire.Msg{T: "manifest_ok"})
			case "ready":
				if err := c.Send(wire.Msg{T: "ready_ok", Streams: h.cfg.Streams}); err != nil {
					return err
				}
			case "keep":
				// idle keepalive from the sender UI
			case "bye":
				return nil
			default:
				return fmt.Errorf("unexpected frame %q on sender control", m.T)
			}
		}
	}()
	if err != nil {
		h.log.Printf("%s sender closed: %v", s.id, err)
	}
	s.close(h.log, name)
}

func (s *session) setManifest(root string, files []wire.File) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("session already closed")
	}
	if s.claimed {
		return fmt.Errorf("a receiver already holds this session")
	}
	if len(files) == 0 {
		return fmt.Errorf("empty manifest")
	}
	if len(files) > 100000 {
		return fmt.Errorf("manifest too large (%d files)", len(files))
	}
	m := make(map[string]wire.File, len(files))
	for _, f := range files {
		if f.ID == "" || f.Name == "" || f.Size < 0 || f.Chunk <= 0 || f.Chunks <= 0 {
			return fmt.Errorf("malformed manifest entry %q", f.Name)
		}
		if _, dup := m[f.ID]; dup {
			return fmt.Errorf("duplicate file id %q", f.ID)
		}
		m[f.ID] = f
	}
	s.root = root
	s.files = m
	var total int64
	for _, f := range files {
		total += f.Size
	}
	s.h.log.Printf("%s offering %d files, %s", s.id, len(files), wire.Human(total))
	return nil
}

// --- sender lanes ---------------------------------------------------------

func (h *hub) handleLane(c *wire.Conn, hello wire.Msg) {
	s, err := h.lookup(hello.Token, c.RemoteAddr())
	if err != nil {
		_ = c.Send(replyError(err))
		return
	}

	l := &lane{c: c, buf: make([]byte, 4<<20), quit: make(chan struct{})}
	if !s.addLane(l) {
		_ = c.Send(wire.ErrMsg("gone", "session is over or the lane pool is full"))
		l.stop()
		return
	}
	if err := c.Send(wire.Msg{T: "lane_ok"}); err != nil {
		s.dropLane(l)
		return
	}
	// A parked lane waits for work, which can be minutes; the per-chunk budget
	// is applied when the lane is handed out instead.
	_ = c.SetDeadline(time.Time{})
	<-l.quit // parked; the connection stays open until the session or pool ends
}

func (s *session) addLane(l *lane) bool {
	s.mu.Lock()
	if s.closed || len(s.lanes) >= cap(s.idle) {
		s.mu.Unlock()
		return false
	}
	s.lanes[l] = struct{}{}
	done := s.doneCh
	s.mu.Unlock()

	go func() {
		select {
		case s.idle <- l:
		case <-done:
			l.stop()
		case <-l.quit:
		}
	}()
	return true
}

func (s *session) dropLane(l *lane) {
	s.mu.Lock()
	known := false
	if _, ok := s.lanes[l]; ok {
		delete(s.lanes, l)
		known = true
	}
	s.mu.Unlock()
	if known {
		l.stop()
	}
}

func (s *session) pullLane(timeout time.Duration) (*lane, error) {
	select {
	case l := <-s.idle:
		return l, nil
	case <-s.doneCh:
		return nil, fmt.Errorf("gone: session ended")
	case <-time.After(timeout):
		return nil, fmt.Errorf("no_lane: sender served nothing in %s (lanes busy, or the sender process died)", timeout)
	}
}

func (s *session) returnLane(l *lane) bool {
	s.mu.Lock()
	alive := !s.closed
	if _, ok := s.lanes[l]; !ok {
		alive = false
	}
	s.mu.Unlock()
	if !alive {
		l.stop()
		return false
	}
	select {
	case s.idle <- l:
		return true
	default:
		s.dropLane(l)
		return false
	}
}

// --- receiver control -----------------------------------------------------

func (h *hub) handleReceiver(c *wire.Conn, hello wire.Msg) {
	s, err := h.lookup(hello.Token, c.RemoteAddr())
	if err != nil {
		_ = c.Send(replyError(err))
		return
	}

	files, root, ok := s.manifest()
	if !ok {
		_ = c.Send(wire.ErrMsg("no_manifest", "the sender has not offered files yet; ask them to finish selecting"))
		return
	}
	name := orName(hello.Name, c.RemoteAddr())
	if !s.claim(name) {
		_ = c.Send(wire.ErrMsg("claimed", "another receiver is already pulling this session: "+s.receiver()))
		return
	}
	s.notifySender(wire.Msg{T: "claimed", Name: name})
	s.killWorkers() // clear any straggler from a previous attempt
	h.log.Printf("%s claimed by %s from %s (%d files)", s.id, name, c.RemoteAddr(), len(files))

	if err := sendManifest(c, s, files, root); err != nil {
		s.unclaim()
		s.notifySender(wire.Msg{T: "receiver_gone"})
		return
	}
	_ = c.Send(wire.Msg{T: "claim_ok", Streams: h.cfg.Streams, Chunk: h.cfg.Chunk})

	for {
		_ = c.SetDeadline(time.Now().Add(controlIdle))
		m, err := c.Recv()
		if err != nil {
			break
		}
		switch m.T {
		case "keep":
		case "progress":
			_ = c.Send(wire.Msg{T: "stats", Bytes: atomic.LoadInt64(&s.served)})
		case "done":
			h.log.Printf("%s receiver %s finished, relayed %s", s.id, name, wire.Human(atomic.LoadInt64(&s.served)))
			s.notifySender(wire.Msg{T: "done", Bytes: m.Bytes, Count: m.Count})
			return
		default:
			_ = c.Send(wire.ErrMsg("frame", fmt.Sprintf("unexpected frame %q on receiver control", m.T)))
		}
	}

	s.unclaim()
	// Close the dead receiver's workers now instead of letting each one burn
	// its splice timeout while holding a sender lane hostage.
	s.killWorkers()
	h.log.Printf("%s receiver %s disconnected", s.id, name)
	s.notifySender(wire.Msg{T: "receiver_gone"})
}

func (s *session) addWorker(c *wire.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workers == nil {
		s.workers = map[*wire.Conn]struct{}{}
	}
	s.workers[c] = struct{}{}
}

func (s *session) removeWorker(c *wire.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.workers, c)
}

// killWorkers closes every data connection belonging to the receiver that just
// left, which frees the sender lanes those connections were parked on.
func (s *session) killWorkers() {
	s.mu.Lock()
	conns := make([]*wire.Conn, 0, len(s.workers))
	for c := range s.workers {
		conns = append(conns, c)
	}
	s.workers = map[*wire.Conn]struct{}{}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func sendManifest(c *wire.Conn, s *session, files []wire.File, root string) error {
	groups := wire.SplitForFraming(files, 200<<10)
	for n, group := range groups {
		m := wire.Msg{
			T:       "manifest",
			Root:    root,
			Files:   group,
			Index:   int64(n),
			Expires: s.expires.Unix(),
			Streams: s.h.cfg.Streams,
			Chunk:   s.h.cfg.Chunk,
			Done:    n == len(groups)-1,
		}
		if err := c.Send(m); err != nil {
			return err
		}
	}
	return nil
}

// --- worker: one chunk per request ----------------------------------------

func (h *hub) handleWorker(c *wire.Conn, hello wire.Msg) {
	s, err := h.lookup(hello.Token, c.RemoteAddr())
	if err != nil {
		_ = c.Send(replyError(err))
		return
	}
	if !s.isClaimed() {
		_ = c.Send(wire.ErrMsg("unclaimed", "open the control connection and pick files first"))
		return
	}
	s.addWorker(c)
	defer s.removeWorker(c)
	if err := c.Send(wire.Msg{T: "worker_ok"}); err != nil {
		return
	}

	for {
		_ = c.SetDeadline(time.Now().Add(controlIdle))
		req, err := c.Recv()
		if err != nil {
			return
		}
		switch req.T {
		case "keep":
			continue
		case "bye":
			return
		case "get":
		default:
			_ = c.Send(wire.ErrMsg("frame", "expected get"))
			return
		}
		err = h.serveChunk(s, c, req)
		if err == nil {
			continue
		}
		code, _ := splitErr(err)
		if perr := c.Send(replyError(err)); perr != nil {
			return
		}
		if code == "bad_request" {
			return
		}
	}
}

func (h *hub) serveChunk(s *session, c *wire.Conn, req wire.Msg) error {
	f, ok := s.get(req.File)
	if !ok {
		return fmt.Errorf("bad_request: unknown file id %q", req.File)
	}
	if req.Index < 0 || req.Index >= f.Chunks {
		return fmt.Errorf("bad_request: chunk %d is outside %s (%d chunks)", req.Index, f.Name, f.Chunks)
	}
	offset, length := wire.ChunkRange(f.Size, f.Chunk, req.Index)
	if length < 0 {
		return fmt.Errorf("bad_request: chunk %d of %s has a negative range", req.Index, f.Name)
	}

	l, err := s.pullLane(laneWait)
	if err != nil {
		return err
	}

	// Any break in this exchange retires the lane: the byte stream may be half
	// consumed, and a lane that is out of frame alignment would poison the next
	// request. The sender re-dials dropped lanes on its own, so retiring one
	// costs a second rather than the session.
	retire := true
	defer func() {
		if retire {
			s.dropLane(l)
		} else {
			s.returnLane(l)
		}
	}()

	budget := time.Duration(length>>20)*1500*time.Millisecond + 30*time.Second
	_ = l.c.SetDeadline(time.Now().Add(budget))
	_ = c.SetDeadline(time.Now().Add(budget))

	if err := l.c.Send(wire.Msg{T: "work", File: f.Name, Index: req.Index, Offset: offset, Length: length}); err != nil {
		return fmt.Errorf("lane_lost: sender lane died: %w", err)
	}
	begin, err := l.c.Recv()
	if err != nil {
		return fmt.Errorf("lane_lost: no begin frame from sender: %w", err)
	}
	if e := begin.AsError(); e != nil {
		return fmt.Errorf("sender_error: %s", e.Text)
	}
	if begin.T != "begin" {
		return fmt.Errorf("lane_lost: expected begin, got %q", begin.T)
	}
	if begin.Length != length {
		return fmt.Errorf("lane_lost: begin says %d bytes, we asked for %d", begin.Length, length)
	}

	// The payload is spliced straight through, then the sender's digest for
	// exactly those bytes follows on the same lane, so the receiver compares
	// what it was handed rather than what the sender meant to send.
	if err := c.Send(wire.Msg{T: "begin", File: req.File, Index: req.Index, Offset: offset, Length: length}); err != nil {
		return fmt.Errorf("receiver_gone: %w", err)
	}
	n, err := io.CopyBuffer(c.Buf(), io.LimitReader(l.c.Raw(), length), l.buf)
	if err != nil {
		return fmt.Errorf("lane_lost: splice broke: %w", err)
	}
	if n != length {
		return fmt.Errorf("lane_lost: short splice, %d of %d bytes", n, length)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("receiver_gone: write to receiver failed: %w", err)
	}

	end, err := l.c.Recv()
	if err != nil {
		return fmt.Errorf("lane_lost: no end frame after %s: %w", wire.Human(length), err)
	}
	if e := end.AsError(); e != nil {
		return fmt.Errorf("sender_error: %s", e.Text)
	}
	if end.T != "end" {
		return fmt.Errorf("lane_lost: expected end, got %q", end.T)
	}
	if len(end.SHA256) != 64 {
		return fmt.Errorf("lane_lost: sender digest %q is not 32 bytes of hex", end.SHA256)
	}
	if _, err := hex.DecodeString(end.SHA256); err != nil {
		return fmt.Errorf("lane_lost: sender digest is not hex: %w", err)
	}
	if err := c.Send(wire.Msg{T: "end", File: req.File, Index: req.Index, SHA256: end.SHA256, Digests: end.Digests, Bytes: n}); err != nil {
		return fmt.Errorf("receiver_gone: receiver vanished before the digest: %w", err)
	}

	atomic.AddInt64(&s.served, n)
	retire = false
	return nil
}

// --- session bookkeeping --------------------------------------------------

func (s *session) get(id string) (wire.File, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[id]
	return f, ok
}

func (s *session) manifest() ([]wire.File, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return nil, s.root, false
	}
	out := make([]wire.File, 0, len(s.files))
	for _, f := range s.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, s.root, true
}

func (s *session) claim(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimed || s.closed {
		return false
	}
	s.claimed = true
	s.recvName = name
	return true
}

func (s *session) unclaim() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimed = false
	s.recvName = ""
}

func (s *session) receiver() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvName
}

func (s *session) isClaimed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimed
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) notifySender(m wire.Msg) {
	s.mu.Lock()
	c := s.sender
	s.mu.Unlock()
	if c != nil {
		_ = c.Send(m)
	}
}

func (s *session) close(lg *log.Logger, name string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	lanes := make([]*lane, 0, len(s.lanes))
	for l := range s.lanes {
		lanes = append(lanes, l)
	}
	s.lanes = map[*lane]struct{}{}
	tok := s.id
	served := atomic.LoadInt64(&s.served)
	close(s.doneCh)
	h := s.h
	s.mu.Unlock()

	for _, l := range lanes {
		l.stop()
	}
	h.forget(tok)
	lg.Printf("%s session from %s closed, relayed %s", short(tok), name, wire.Human(served))
}

// janitor drops sessions that outlived their token without anyone noticing.
func (h *hub) janitor() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		now := time.Now()
		h.mu.Lock()
		expired := make([]*session, 0)
		for _, s := range h.sess {
			if now.After(s.expires) {
				expired = append(expired, s)
			}
		}
		h.mu.Unlock()
		for _, s := range expired {
			h.log.Printf("%s expired", s.id)
			s.close(h.log, "expired")
		}

		h.fmu.Lock()
		for ip, f := range h.failures {
			if now.After(f.until) {
				delete(h.failures, ip)
			}
		}
		h.fmu.Unlock()
	}
}

// --- small helpers --------------------------------------------------------

func replyError(err error) wire.Msg {
	code, text := splitErr(err)
	return wire.ErrMsg(code, text)
}

func splitErr(err error) (string, string) {
	msg := err.Error()
	if parts := strings.SplitN(msg, ": ", 2); len(parts) == 2 {
		return parts[0], msg
	}
	return "relay", msg
}

func short(token string) string {
	if len(token) < 4 {
		return token
	}
	return token[:4]
}

func orName(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// sharedPublicPort reads publicport= from the same per-user config the client
// uses, so a double-clicked relay forwards the port the user already picked.
func sharedPublicPort() int {
	path := filepath.Join(os.TempDir(), "STRS", "config")
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.ToLower(strings.TrimSpace(k)) != "publicport" {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 0
}

// portInUse asks whatever holds the port whether it answers, which turns a
// bind failure into the real message: a relay is already up.
func portInUse(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
