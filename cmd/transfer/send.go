package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"transfer/internal/wire"
)

// sendMember is one real file inside a packed stream.
type sendMember struct {
	wire.Member
	abs string
}

// sendSource is what a manifest name resolves to: one file, or a run of small
// files concatenated into a single stream.
type sendSource struct {
	name    string
	abs     string
	members []sendMember
	fc      *fileCrypto
}

// sender holds the state of one `transfer send` run.
type sender struct {
	// 64-bit counters used with sync/atomic come first: on 32-bit ARM (a
	// Raspberry Pi) they must sit on an 8-byte boundary or the program panics.
	served int64
	chunks int64

	control       *wire.Conn
	serverAddr    string
	code          string
	pin           string
	sources       map[string]*sendSource
	total         int64
	packed        int64
	started       time.Time
	peer          string
	doneBytes     int64
	doneCount     int64
	mu            sync.Mutex
	lanes         []*laneIO
	digests       map[string]map[int64]string
	memberDigests map[string]string

	stop chan struct{}
}

type laneIO struct {
	c   *wire.Conn
	buf []byte
}

// copyBlock is the read/write granularity on a lane. 4 MiB keeps a gigabit link
// busy without asking the OS for a huge buffer eighty times a second.
const copyBlock = 4 << 20

func (s *sender) laneAt(i int) *laneIO {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.lanes) {
		return nil
	}
	return s.lanes[i]
}

func (s *sender) setLane(i int, l *laneIO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.lanes) <= i {
		s.lanes = append(s.lanes, nil)
	}
	s.lanes[i] = l
}

func (s *sender) snapshotLanes() []*laneIO {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*laneIO, 0, len(s.lanes))
	for _, l := range s.lanes {
		if l != nil {
			out = append(out, l)
		}
	}
	return out
}

func (s *sender) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	dir := fs.String("dir", "", "folder to scan (default: this exe's folder)")
	server := fs.String("server", "", "relay host:port")
	pin := fs.String("pin", "", "expected relay certificate pin")
	all := fs.Bool("all", false, "offer everything found without asking")
	flat := fs.Bool("flat", false, "do not recurse into subfolders")
	exc := fs.String("exclude", "", "comma separated name patterns to skip")
	streams := fs.Int("streams", 0, "parallel data lanes (capped by the relay)")
	chunkMB := fs.Int64("chunk", 0, "chunk size in MB for medium and large files")
	packMB := fs.Int64("pack", -1, "fold files this size or smaller into one stream (0 disables)")
	show := fs.Int("show", 400, "picker rows to list (0 for all)")
	passwordFlag := fs.String("password", "", "password your friend types (default: saved, or ask)")
	fs.Parse(args)

	root, err := resolveDir(*dir)
	if err != nil {
		return err
	}
	// Sending always hosts the relay on this machine. The saved server setting
	// belongs to receiving - on a friend's PC it points at the sender's relay,
	// and offering files through that would hand out the wrong address.
	serverAddr := strings.TrimSpace(*server)
	if serverAddr == "" {
		serverAddr = localRelayAddr()
	}
	wantChunk := appCfg.Chunk
	if *chunkMB > 0 {
		wantChunk = (*chunkMB) << 20
	}
	wantPack := appCfg.Pack
	if *packMB >= 0 {
		wantPack = (*packMB) << 20
	}
	wantStreams := appCfg.Streams
	if *streams > 0 {
		wantStreams = *streams
	}

	// When the relay is meant to be this PC, host it right here: one window,
	// one program, nothing else to start.
	if srv, err := maybeHostRelay(serverAddr); err != nil {
		return err
	} else if srv != nil {
		defer func() { srv.Close(); hostedRelay = nil }()
	}

	if err := ensureRelay(serverAddr); err != nil {
		return err
	}
	password, err := resolvePassword(*passwordFlag)
	if err != nil {
		return err
	}
	wantPin, pinAuthoritative := expectedPin(serverAddr, *pin)
	c, reply, gotPin, err := openConn(serverAddr, "sender", password, hostLabel(), wantPin)
	if err != nil {
		return err
	}
	if err := expectReply(c, reply, "token"); err != nil {
		return err
	}
	defer c.Close()
	if err := rememberPin(serverAddr, gotPin, pinAuthoritative); err != nil {
		return err
	}

	// The relay echoes back the derived token it was given. What friends
	// type is the password itself, so that is the code.
	code := password
	expires := time.Unix(reply.Expires, 0)
	laneCap := reply.Streams
	if laneCap < 1 || laneCap > wantStreams {
		laneCap = wantStreams
	}
	endpoint := reply.Endpoint
	if endpoint == "" {
		endpoint = serverAddr
	}
	if endpoint != serverAddr {
		say("relay advertises itself as %s, using that in the handoff block", endpoint)
	}

	s := &sender{
		control:       c,
		serverAddr:    serverAddr,
		code:          code,
		pin:           gotPin,
		sources:       map[string]*sendSource{},
		started:       time.Now(),
		digests:       map[string]map[int64]string{},
		memberDigests: map[string]string{},
		stop:          make(chan struct{}),
	}

	// Step 1 of the brief: the code is live the moment the relay answers, so
	// the friend can start while you pick. It goes to the console and nowhere
	// else - no file to find later, no file to leave lying around.
	printHandoff(code, endpoint, gotPin, expires)
	go s.holdControl()

	// Step 2: scan and select.
	items, err := scanFolder(root, splitList(*exc), !*flat)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("nothing to send in %s - drop files in that folder, or run: STRS.exe send -dir <folder>", root)
	}
	absOf := map[string]string{}
	planned := planFiles(items, wantChunk)
	for i, it := range items {
		absOf[planned[i].Name] = it.abs
	}
	say("found %d files in %s", len(planned), root)

	picked, err := chooseFiles("Send Which Files", planned, *all, *show)
	if err != nil {
		return err
	}

	// Small files ride together; the manifest the friend sees is the packed
	// view, and each stream resolves back to real paths here.
	manifest := packSmallFiles(picked, wantPack)
	for i := range manifest {
		manifest[i].Nonce = newNonce()
	}
	var total int64
	packs := 0
	for _, f := range manifest {
		total += f.Size
		src := &sendSource{name: f.Name}
		if len(f.Members) > 0 {
			packs++
			for _, m := range f.Members {
				abs, ok := absOf[m.Name]
				if !ok {
					return fmt.Errorf("lost the path for %s between scan and send", m.Name)
				}
				src.members = append(src.members, sendMember{Member: m, abs: abs})
			}
		} else {
			abs, ok := absOf[f.Name]
			if !ok {
				return fmt.Errorf("lost the path for %s between scan and send", f.Name)
			}
			src.abs = abs
		}
		fc, ferr := fileCryptoFor(password, f.Nonce)
		if ferr != nil {
			return ferr
		}
		src.fc = fc
		s.sources[f.Name] = src
	}
	s.total = total
	s.packed = int64(packs)

	if err := sendManifest(c, root, manifest); err != nil {
		return err
	}
	printOffer(manifest, len(picked), packs, total)
	say("waiting for your friend to type the password %s", code)

	// Open the data lanes the relay will feed from. Lanes dial the address we
	// already reached, not the advertised one, so a LAN sender does not have to
	// hairpin through the router.
	for i := 0; i < laneCap; i++ {
		lc, lm, _, err := openConn(serverAddr, "lane", code, hostLabel(), gotPin)
		if err != nil {
			return fmt.Errorf("lane %d: %w", i+1, err)
		}
		if err := expectReply(lc, lm, "lane_ok"); err != nil {
			return fmt.Errorf("lane %d: %w", i+1, err)
		}
		_ = lc.SetDeadline(time.Time{})
		s.setLane(i, &laneIO{c: lc, buf: make([]byte, copyBlock)})
	}
	readyCount := len(s.snapshotLanes())
	if err := c.Send(wire.Msg{T: "ready", Streams: readyCount}); err != nil {
		return err
	}
	rm, err := c.Recv()
	if err != nil {
		return err
	}
	if e := rm.AsError(); e != nil {
		return e
	}
	if rm.T != "ready_ok" {
		return fmt.Errorf("expected ready_ok, got %q", rm.T)
	}

	say("ready: %s over %d lanes. waiting for a receiver (Ctrl-C to stop)", wire.Human(total), readyCount)

	var wg sync.WaitGroup
	for i := 0; i < readyCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.maintainLane(i)
		}(i)
	}
	wg.Add(1)
	done := make(chan string, 1)
	go func() {
		defer wg.Done()
		done <- s.listenControl()
	}()
	go s.ticker()

	reason := <-done
	close(s.stop)
	_ = closeQuietly(c)
	for _, l := range s.snapshotLanes() {
		_ = closeQuietly(l.c)
	}
	wgWait(&wg)

	clearStatus()
	fmt.Println()
	fmt.Printf("session %s ended (%s)\n", code, reason)
	if s.doneCount > 0 {
		fmt.Printf("receiver verified %d files, %s - every chunk hash matched and the sizes on disk agree\n",
			s.doneCount, wire.Human(s.doneBytes))
	}
	fmt.Printf("relayed %s for %s selected in %s across %d chunk requests\n",
		wire.Human(atomic.LoadInt64(&s.served)), wire.Human(total),
		time.Since(s.started).Round(time.Second), atomic.LoadInt64(&s.chunks))
	fmt.Println("(relayed can exceed the selection when a receiver re-requests a chunk)")
	printSenderDigests(manifest, s)
	if reason == "done" {
		fmt.Println("\nthe friend's copy was checked file by file; ask them to compare the digests above")
	}
	return nil
}

// printSenderDigests lists the per-file hashes so the two humans can compare
// them against the receiver's report.
func printSenderDigests(manifest []wire.File, s *sender) {
	if len(manifest) > 60 {
		fmt.Printf("\nskipping the digest list: %d entries is a lot to eyeball, the receiver still checked every chunk\n", len(manifest))
		return
	}
	fmt.Println("\nper-file SHA-256 - the receiver prints the same values, they must match:")
	for _, f := range manifest {
		if len(f.Members) > 0 {
			for _, m := range f.Members {
				fmt.Printf("  %-10s %-40s %s\n", wire.Human(m.Length), m.Name, s.memberDigest(m.Name))
			}
			continue
		}
		fmt.Printf("  %-10s %-40s %s\n", wire.Human(f.Size), f.Name, s.chainDigest(f.Name, f.Chunks))
	}
}

func (s *sender) memberDigest(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.memberDigests[name]; ok {
		return d
	}
	return "not served"
}

func (s *sender) chainDigest(name string, chunks int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.digests[name]
	if int64(len(m)) < chunks {
		return fmt.Sprintf("incomplete (%d/%d chunks)", len(m), chunks)
	}
	raw := make([][]byte, 0, chunks)
	for i := int64(0); i < chunks; i++ {
		b, err := hex.DecodeString(m[i])
		if err != nil {
			return "unreadable digest"
		}
		raw = append(raw, b)
	}
	return wire.FileDigest(raw)
}

// maintainLane keeps slot i staffed. The relay drops a lane when the friend's
// side breaks mid-chunk, and a session with no lanes serves nothing, so a dead
// lane is replaced rather than mourned.
func (s *sender) maintainLane(i int) {
	backoff := time.Second
	for {
		l := s.laneAt(i)
		if l == nil || s.stopping() {
			return
		}
		err := s.pumpLane(l)
		if err == nil || s.stopping() {
			return
		}
		say("lane %d dropped (%v), reconnecting", i+1, err)
		select {
		case <-s.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
		_ = closeQuietly(l.c)

		lc, lm, _, derr := openConn(s.serverAddr, "lane", s.code, hostLabel(), s.pin)
		if derr != nil {
			// A dead token or a closed session is final; a socket blip is not.
			msg := derr.Error()
			if strings.Contains(msg, "gone") || strings.Contains(msg, "bad_token") || strings.Contains(msg, "expired") {
				say("lane %d will not come back: %v", i+1, derr)
				return
			}
			continue
		}
		if err := expectReply(lc, lm, "lane_ok"); err != nil {
			_ = closeQuietly(lc)
			continue
		}
		_ = lc.SetDeadline(time.Time{})
		s.setLane(i, &laneIO{c: lc, buf: l.buf})
		backoff = time.Second
		say("lane %d back up", i+1)
	}
}

// pumpLane answers work requests for as long as the relay keeps this lane alive.
func (s *sender) pumpLane(l *laneIO) error {
	for {
		m, err := l.c.Recv()
		if err != nil {
			return err
		}
		if m.T != "work" {
			_ = l.c.Send(wire.ErrMsg("frame", "expected work on a lane"))
			return fmt.Errorf("unexpected frame %q on a lane", m.T)
		}
		if err := s.ship(l, m); err != nil {
			code, text := splitErrorText(err)
			if sendErr := l.c.Send(wire.ErrMsg(code, text)); sendErr != nil {
				return sendErr
			}
			return fmt.Errorf("%s", text)
		}
	}
}

// ship answers one work request, choosing the packed or plain path.
func (s *sender) ship(l *laneIO, work wire.Msg) error {
	src, ok := s.sources[work.File]
	if !ok {
		return fmt.Errorf("bad_request: %s is not in this session", work.File)
	}
	if len(src.members) > 0 {
		return s.shipPack(l, src, work)
	}
	return s.shipRange(l, src, work)
}

// shipRange reads one byte range, hashes it as it goes, and writes the digest
// after the payload so no chunk has to be held in memory.
func (s *sender) shipRange(l *laneIO, src *sendSource, work wire.Msg) error {
	digest, err := s.streamRange(l, src.abs, work.Offset, work.Length, work.File, work.Index, src.fc)
	if err != nil {
		return err
	}
	s.recordDigest(work.File, work.Index, digest)
	return l.c.Send(wire.Msg{T: "end", SHA256: digest, Mac: src.fc.mac(src.name, work.Index, work.Length, digest), Bytes: work.Length})
}

// shipPack streams a run of small files as one payload. A pack is always one
// chunk, so the range covers the whole concatenation.
func (s *sender) shipPack(l *laneIO, src *sendSource, work wire.Msg) error {
	var total int64
	for _, m := range src.members {
		total += m.Length
	}
	if work.Offset != 0 || work.Length != total {
		return fmt.Errorf("bad_request: pack %s is served whole (%s bytes at 0), asked for %s at %d", work.File, wire.Human(total), wire.Human(work.Length), work.Offset)
	}
	if err := l.c.Send(wire.Msg{T: "begin", Length: total}); err != nil {
		return err
	}

	packHash := sha256.New()
	enc := src.fc.stream(0)
	digests := make([]string, 0, len(src.members))
	var written int64
	for _, m := range src.members {
		h := sha256.New()
		if err := s.copyFileInto(l, m.abs, m.Length, enc, h, packHash); err != nil {
			return err
		}
		digests = append(digests, wire.HexDigest(h.Sum(nil)))
		written += m.Length
		s.recordMemberDigest(m.Name, digests[len(digests)-1])
	}
	if written != total {
		return fmt.Errorf("short_read: pack assembled %s of %s", wire.Human(written), wire.Human(total))
	}
	if err := l.c.Flush(); err != nil {
		return fmt.Errorf("flush_failed: %w", err)
	}
	atomic.AddInt64(&s.chunks, 1)
	packDigest := wire.HexDigest(packHash.Sum(nil))
	return l.c.Send(wire.Msg{T: "end", SHA256: packDigest, Digests: digests, Mac: src.fc.mac(src.name, 0, total, packDigest), Bytes: written})
}

// copyFileInto streams one whole file into the lane and any extra writers,
// which is how the pack digest and every member digest come from one read.
func (s *sender) copyFileInto(l *laneIO, abs string, length int64, enc cipher.Stream, sinks ...io.Writer) error {
	f, err := os.Open(abs)
	if err != nil {
		return fmt.Errorf("open_failed: %w", err)
	}
	defer f.Close()
	if length == 0 {
		return nil
	}
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat_failed: %w", err)
	}
	if st.Size() < length {
		return fmt.Errorf("file_shrank: %s is now %s", abs, wire.Human(st.Size()))
	}
	var done int64
	for done < length {
		want := int64(len(l.buf))
		if rest := length - done; rest < want {
			want = rest
		}
		n, rerr := f.ReadAt(l.buf[:want], done)
		if n > 0 {
			// hash the plaintext, then encrypt in place and send
			for _, w := range sinks {
				_, _ = w.Write(l.buf[:n])
			}
			enc.XORKeyStream(l.buf[:n], l.buf[:n])
			if _, werr := l.c.Buf().Write(l.buf[:n]); werr != nil {
				return fmt.Errorf("write_failed: %w", werr)
			}
			done += int64(n)
			atomic.AddInt64(&s.served, int64(n))
		}
		if rerr != nil {
			if rerr == io.EOF || done >= length {
				break
			}
			return fmt.Errorf("read_failed: %w", rerr)
		}
	}
	if done != length {
		return fmt.Errorf("short_read: %s gave %s of %s", abs, wire.Human(done), wire.Human(length))
	}
	return nil
}

// streamRange is the plain-file path: one open, one read loop, one hash.
func (s *sender) streamRange(l *laneIO, abs string, offset, length int64, name string, index int64, fc *fileCrypto) (string, error) {
	if offset%16 != 0 {
		return "", fmt.Errorf("bad_request: chunk offset %d is not 16-byte aligned", offset)
	}
	f, err := os.Open(abs)
	if err != nil {
		return "", fmt.Errorf("open_failed: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat_failed: %w", err)
	}
	if st.Size() < offset+length {
		return "", fmt.Errorf("file_shrank: %s is now %s, re-offer it to fix the manifest", name, wire.Human(st.Size()))
	}

	if err := l.c.Send(wire.Msg{T: "begin", Length: length}); err != nil {
		return "", err
	}
	h := sha256.New()
	enc := fc.stream(offset)
	var done int64
	for done < length {
		want := int64(len(l.buf))
		if rest := length - done; rest < want {
			want = rest
		}
		n, rerr := f.ReadAt(l.buf[:want], offset+done)
		if n > 0 {
			_, _ = h.Write(l.buf[:n])
			enc.XORKeyStream(l.buf[:n], l.buf[:n])
			if _, werr := l.c.Buf().Write(l.buf[:n]); werr != nil {
				return "", fmt.Errorf("write_failed: %w", werr)
			}
			done += int64(n)
			atomic.AddInt64(&s.served, int64(n))
		}
		if rerr != nil {
			if rerr == io.EOF || done >= length {
				break
			}
			return "", fmt.Errorf("read_failed: %w", rerr)
		}
	}
	if done != length {
		return "", fmt.Errorf("short_read: got %s of %s for %s chunk %d", wire.Human(done), wire.Human(length), name, index)
	}
	if err := l.c.Flush(); err != nil {
		return "", fmt.Errorf("flush_failed: %w", err)
	}
	atomic.AddInt64(&s.chunks, 1)
	return wire.HexDigest(h.Sum(nil)), nil
}

func (s *sender) recordDigest(name string, index int64, digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.digests[name] == nil {
		s.digests[name] = map[int64]string{}
	}
	s.digests[name][index] = digest
}

func (s *sender) recordMemberDigest(name, digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memberDigests[name] = digest
}

func (s *sender) listenControl() string {
	for {
		_ = s.control.SetDeadline(time.Now().Add(5 * time.Minute))
		m, err := s.control.Recv()
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				continue
			}
			return "disconnected"
		}
		switch m.T {
		case "claimed":
			s.peer = m.Name
			say("receiver connected: %s is pulling the session", orBlank(m.Name, "your friend"))
		case "receiver_gone":
			say("receiver disconnected - they can re-run with the same code while this window stays open")
		case "done":
			s.doneBytes = m.Bytes
			s.doneCount = m.Count
			return "done"
		case "error":
			return "relay error: " + m.Err
		default:
			_ = s.control.Send(wire.ErrMsg("frame", "unexpected "+m.T))
			return "protocol"
		}
	}
}

// holdControl keeps the sender channel alive while the user is still scanning
// and picking. Without it the relay's idle timeout ends the session mid-pick
// and the next keypress fails on a dead socket.
func (s *sender) holdControl() {
	tick := time.NewTicker(45 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			if err := s.control.Send(wire.Msg{T: "keep"}); err != nil {
				return
			}
		}
	}
}

// ticker repaints the progress line while lanes are moving bytes.
func (s *sender) ticker() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var last int64
	var rate float64
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			cur := atomic.LoadInt64(&s.served)
			if hostedRelay != nil {
				if n := hostedRelay.Served(); n > 0 {
					cur = n // what actually reached the receiver
				}
			}
			delta := cur - last
			last = cur
			if delta > 0 {
				rate = rate*0.7 + float64(delta)
			}
			elapsed := time.Since(s.started).Round(time.Second)
			status(fmt.Sprintf("served %s / %s  @ %s/s  lanes %d  peer %s  [%s]",
				wire.Human(cur), wire.Human(s.total), wire.Human(int64(rate)),
				len(s.snapshotLanes()), orBlank(s.peer, "-"), elapsed))
		}
	}
}

// sendManifest pushes the file list, split so no frame gets too big for the
// relay to read.
func sendManifest(c *wire.Conn, root string, files []wire.File) error {
	groups := wire.SplitForFraming(files, 200<<10)
	for n, group := range groups {
		m := wire.Msg{T: "manifest", Root: root, Files: group, Index: int64(n), Done: n == len(groups)-1}
		if err := c.Send(m); err != nil {
			return err
		}
	}
	rm, err := c.Recv()
	if err != nil {
		return err
	}
	if e := rm.AsError(); e != nil {
		return e
	}
	if rm.T != "manifest_ok" {
		return fmt.Errorf("expected manifest_ok, got %q", rm.T)
	}
	return nil
}

// printHandoff prints the three values the friend needs, framed so they are
// easy to read out or copy. This is the whole handoff - there is no file.

// printOffer lists what is on the table, expanding packs back into the real
// file names a person recognises.
func printOffer(manifest []wire.File, picked, packs int, total int64) {
	say("offering %d files as %d streams (%d of them packs), %s", picked, len(manifest), packs, wire.Human(total))
	files := expandForDisplay(manifest)
	if len(files) > 40 {
		fmt.Printf("   ... not listing %d names, the friend's picker shows them all\n", len(files))
		return
	}
	for _, f := range files {
		fmt.Printf("    %10s  %-6s  %s\n", wire.Human(f.Size), f.Class, f.Name)
	}
}

// expandForDisplay turns packed manifest entries back into per-file rows.
func expandForDisplay(files []wire.File) []wire.File {
	var out []wire.File
	for _, f := range files {
		if len(f.Members) == 0 {
			out = append(out, f)
			continue
		}
		for _, m := range f.Members {
			out = append(out, wire.File{Name: m.Name, Size: m.Length, Mtime: m.Mtime, Class: wire.ClassOf(m.Length)})
		}
	}
	return out
}

func closeQuietly(c *wire.Conn) error {
	if c == nil {
		return nil
	}
	return c.Close()
}

func wgWait(wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func splitErrorText(err error) (string, string) {
	msg := err.Error()
	if parts := strings.SplitN(msg, ": ", 2); len(parts) == 2 {
		return parts[0], msg
	}
	return "sender", msg
}

func orBlank(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
func printHandoff(code, endpoint, pin string, expires time.Time) {
	fmt.Println()
	fmt.Println("  ------------------------ the block ------------------------")
	fmt.Printf("  endpoint  : %s\n", endpoint)
	fmt.Printf("  pin       : %s\n", pin)
	fmt.Printf("  expires   : %s\n", expires.Format("2006-01-02 15:04"))
	fmt.Println("  ----------------------------------------------------------")
	fmt.Printf("  password  : %s\n", code)
	fmt.Println("  ----------------------------------------------------------")
	fmt.Println("  send them the block first, then the password.")
	fmt.Println("  keep this window open: the session dies when the sender does.")
	fmt.Println()
}
