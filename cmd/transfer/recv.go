package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"transfer/internal/wire"
)

// stream is one manifest entry the receiver intends to pull, plus the real
// files inside it that were actually selected.
type stream struct {
	file   wire.File
	wanted []string // member names to write; empty for a plain file
}

// displayRow is one line of the receive picker. Packed small files show up as
// the files they really are, and each row remembers which stream carries it.
type displayRow struct {
	name   string
	size   int64
	class  string
	stream int
	member int // -1 when the stream is a plain file
}

// receiver holds one receive run.
type receiver struct {
	password string
	server   string
	pin      string
	control  *wire.Conn
	outRoot  string
	state    *dlState
	streams  []stream
	got      int64
	total    int64
	chunks   int64
	started  time.Time
	abort    atomic.Value
	stopOnce sync.Once
	stop     chan struct{}
	handles  *filePool
	queue    *workQueue
}

type filePool struct {
	mu sync.Mutex
	m  map[string]*os.File
}

func newFilePool() *filePool { return &filePool{m: map[string]*os.File{}} }

// get opens or reuses the destination handle for one output path. Concurrent
// WriteAt calls on one handle are fine: Go issues them overlapped with an
// explicit offset, so parallel lanes can land chunks anywhere in the file.
func (p *filePool) get(key, path string, size int64) (*os.File, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f, ok := p.m[key]; ok {
		return f, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot size %s to %s: %w", filepath.Base(path), wire.Human(size), err)
	}
	p.m[key] = f
	return f, nil
}

func (p *filePool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, f := range p.m {
		_ = f.Close()
		delete(p.m, k)
	}
}

func cmdReceive(args []string) error {
	// Receiving has nothing to do with this machine's own relay, so start on a
	// clean screen instead of under a "relay connected" line that only ever
	// describes the sender's side.
	if isTerminal() {
		clearScreen()
		fmt.Println(banner())
		fmt.Println()
	}

	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	passF := fs.String("password", "", "the password your friend set")
	codeF := fs.String("code", "", "alias for -password (older wording)")
	fromF := fs.String("from", "", "a text file holding the block your friend sent")
	serverF := fs.String("server", "", "relay host:port")
	pinF := fs.String("pin", "", "expected relay certificate pin")
	outF := fs.String("out", "", "folder to drop the files in")
	allF := fs.Bool("all", false, "take every offered file without asking")
	streamsF := fs.Int("streams", 0, "parallel data lanes")
	verifyF := fs.Bool("verify", true, "re-hash chunks already on disk before trusting them")
	forceF := fs.Bool("fresh", false, "ignore any partial download and start over")
	showF := fs.Int("show", 400, "picker rows to list (0 for all)")
	fs.Parse(args)

	typed := strings.TrimSpace(*passF)
	if typed == "" {
		typed = strings.TrimSpace(*codeF)
	}

	var pasted, barePassword string
	switch {
	case strings.TrimSpace(*fromF) != "":
		b, err := os.ReadFile(*fromF)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", *fromF, err)
		}
		pasted = string(b)
	default:
		if typed == "" {
			v, bare, err := readPaste()
			if err != nil {
				return err
			}
			if bare {
				barePassword = v
			} else {
				pasted = v
			}
		}
	}

	pPassword, pEndpoint, pPin := parsePaste(pasted)
	password := typed
	if password == "" {
		password = barePassword
	}
	if password == "" {
		password = pPassword
	}
	if password == "" {
		password = strings.TrimSpace(askPlain("Password", ""))
	}
	if password == "" {
		return errors.New("no password: pass -password, -from, or paste the block when asked")
	}
	serverAddr, err := resolveServer(*serverF, pEndpoint)
	if err != nil {
		return err
	}

	// A password alone says nothing about where the relay lives. If the address
	// on hand is this PC's own loopback, the block is the only thing that can
	// route to the sender, so demand it rather than dialing into the void.
	bareEntry := typed == "" && pEndpoint == ""
	if bareEntry && isLocalHost(hostOf(serverAddr)) {
		return fmt.Errorf("a password on its own does not say which relay to use - paste the whole block, or choose 3 (friend mode) and it will ask for the address once")
	}
	suppliedPin := *pinF
	if strings.TrimSpace(suppliedPin) == "" {
		suppliedPin = pPin
	}
	wantStreams := appCfg.Streams
	if *streamsF > 0 {
		wantStreams = *streamsF
	}

	say("connecting to relay %s", serverAddr)
	wantPin, pinAuthoritative := expectedPin(serverAddr, suppliedPin)
	c, first, gotPin, err := openConn(serverAddr, "receiver", password, "", wantPin)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := rememberPin(serverAddr, gotPin, pinAuthoritative); err != nil {
		return err
	}

	manifest, expires, lanes, err := collectManifest(c, first, wantStreams)
	if err != nil {
		return err
	}
	if lanes > wantStreams {
		lanes = wantStreams
	}
	if len(manifest) == 0 {
		return errors.New("the sender offered no files")
	}

	rows := displayRows(manifest)
	fmt.Printf("\nsession on %s", serverAddr)
	if !expires.IsZero() {
		fmt.Printf(", expires %s", expires.Format("2006-01-02 15:04"))
	}
	fmt.Println()
	fmt.Println()

	pickedRows, err := chooseRows(rows, *allF, *showF)
	if err != nil {
		return err
	}
	streams := planStreams(manifest, pickedRows)
	if len(streams) == 0 {
		return errors.New("nothing selected")
	}

	outRoot, err := resolveDropFolder(*outF)
	if err != nil {
		return err
	}
	var total int64
	for _, st := range streams {
		total += st.file.Size
	}
	if err := checkSpace(outRoot, total); err != nil {
		return err
	}

	if *forceF {
		if err := os.Remove(statePath(outRoot)); err != nil && !os.IsNotExist(err) {
			say("could not clear the saved progress: %v", err)
		}
	}
	st := loadDLState(outRoot)
	reset := st.reconcile(streams)
	if len(reset) > 0 {
		say("progress reset for %s (the sender changed the file or its chunk plan)", humanList(reset))
	}

	r := &receiver{
		password: password,
		server:   serverAddr,
		pin:      gotPin,
		control:  c,
		outRoot:  outRoot,
		state:    st,
		streams:  streams,
		total:    total,
		started:  time.Now(),
		stop:     make(chan struct{}),
		handles:  newFilePool(),
		queue:    newWorkQueue(),
	}

	if adopted := r.adoptExisting(); adopted > 0 {
		say("%d file(s) are already in the drop folder and match the receipt - skipping them", adopted)
		if err := st.save(); err != nil {
			return err
		}
	}

	if *verifyF {
		if err := r.reverify(); err != nil {
			return err
		}
	}

	// Smallest stream first: the little files finish early and stay usable, and
	// the big ones soak up the tail of the transfer.
	order := make([]stream, len(streams))
	copy(order, streams)
	sort.Slice(order, func(i, j int) bool { return order[i].file.Size < order[j].file.Size })

	var queued int64
	for _, s := range order {
		for _, idx := range st.pending(s.file) {
			if !r.queue.push(chunkJob{id: s.file.ID, index: idx}) {
				return errors.New("nothing to pull")
			}
			queued++
		}
	}

	if queued == 0 {
		say("everything is already downloaded in %s - finishing off", outRoot)
		if err := r.finish(); err != nil {
			return err
		}
		return r.report(nil)
	}

	workers := lanes
	if int64(workers) > queued {
		workers = int(queued)
	}
	say("pulling %d chunk requests over %d lanes into %s (%d streams, %d of them packs)",
		queued, workers, outRoot, len(streams), countPacks(streams))

	go r.keepalive()

	// Ctrl-C or closing the window mid-download throws the half-written files
	// away, so a stopped transfer leaves nothing behind in the drop folder.
	intr := make(chan os.Signal, 1)
	signal.Notify(intr, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-intr; !ok {
			return
		}
		r.stopNow()
		r.handles.closeAll()
		time.Sleep(300 * time.Millisecond)
		r.discardPartial()
		fmt.Println("\nstopped - partial downloads deleted")
		os.Exit(130)
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.runWorker(); err != nil {
				r.fail(err)
			}
		}()
	}
	go r.progress()
	wg.Wait()
	signal.Stop(intr)
	close(intr)
	r.stopNow()
	r.handles.closeAll()

	errs := r.collectedErrs()
	if len(errs) == 0 {
		if err := r.finish(); err != nil {
			errs = append(errs, err)
		} else {
			// Tell the sender what actually landed, so its side can say the
			// sizes and hashes matched without anyone running a checker.
			_ = c.Send(wire.Msg{T: "done", Bytes: r.total, Count: int64(r.countWritten())})
		}
	}
	return r.report(errs)
}

// displayRows expands the manifest into real file names, sorted, so the picker
// shows a normal tree even though small files travel in packs.
func displayRows(manifest []wire.File) []displayRow {
	var rows []displayRow
	for i, f := range manifest {
		if len(f.Members) == 0 {
			rows = append(rows, displayRow{name: f.Name, size: f.Size, class: f.Class, stream: i, member: -1})
			continue
		}
		for j, m := range f.Members {
			rows = append(rows, displayRow{name: m.Name, size: m.Length, class: wire.ClassOf(m.Length), stream: i, member: j})
		}
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].name < rows[b].name })
	return rows
}

func chooseRows(rows []displayRow, all bool, show int) ([]int, error) {
	names := make([]string, len(rows))
	sizes := make([]int64, len(rows))
	for i, r := range rows {
		names[i], sizes[i] = r.name, r.size
	}
	if all {
		out := make([]int, len(rows))
		for i := range out {
			out[i] = i
		}
		return out, nil
	}
	renderRows(buildRows(names, sizes), show)
	for {
		spec := ask("Receive Which Files", "all")
		idx, err := parseSelection(spec, len(names))
		if err != nil {
			fmt.Println("  ", err)
			continue
		}
		if len(idx) == 0 {
			fmt.Println("   nothing selected - type all, or numbers like 1,4,7-9, or q to stop")
			if strings.EqualFold(strings.TrimSpace(spec), "q") {
				return nil, errors.New("cancelled")
			}
			continue
		}
		return idx, nil
	}
}

// planStreams collapses the picked display rows into the streams that have to
// be pulled, and the member names each of those should actually write.
func planStreams(manifest []wire.File, picked []int) []stream {
	rows := displayRows(manifest)
	wanted := map[int]map[string]bool{}
	for _, ri := range picked {
		r := rows[ri]
		if wanted[r.stream] == nil {
			wanted[r.stream] = map[string]bool{}
		}
		if r.member < 0 {
			wanted[r.stream][manifest[r.stream].Name] = true
			continue
		}
		wanted[r.stream][manifest[r.stream].Members[r.member].Name] = true
	}
	var out []stream
	for i, f := range manifest {
		w, ok := wanted[i]
		if !ok {
			continue
		}
		names := make([]string, 0, len(w))
		for n := range w {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, stream{file: f, wanted: names})
	}
	return out
}

func countPacks(streams []stream) int {
	n := 0
	for _, s := range streams {
		if len(s.file.Members) > 0 {
			n++
		}
	}
	return n
}

// collectManifest drains the manifest frames and the claim_ok that follows.
func collectManifest(c *wire.Conn, first wire.Msg, maxStreams int) ([]wire.File, time.Time, int, error) {
	var (
		files   []wire.File
		expires time.Time
		streams = maxStreams
		m       = first
		err     error
	)
	for {
		if m.T != "manifest" {
			return nil, time.Time{}, 0, fmt.Errorf("expected manifest, got %q", m.T)
		}
		files = append(files, m.Files...)
		if m.Expires > 0 {
			expires = time.Unix(m.Expires, 0)
		}
		if m.Streams > 0 && m.Streams < streams {
			streams = m.Streams
		}
		if m.Done {
			break
		}
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		if m, err = c.Recv(); err != nil {
			return nil, time.Time{}, 0, fmt.Errorf("manifest did not arrive: %w", err)
		}
		if e := m.AsError(); e != nil {
			return nil, time.Time{}, 0, e
		}
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if m, err = c.Recv(); err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("claim was not accepted: %w", err)
	}
	_ = c.SetDeadline(time.Time{})
	if e := m.AsError(); e != nil {
		return nil, time.Time{}, 0, e
	}
	if m.T != "claim_ok" {
		return nil, time.Time{}, 0, fmt.Errorf("expected claim_ok, got %q", m.T)
	}
	if m.Streams > 0 && m.Streams < streams {
		streams = m.Streams
	}
	if streams < 1 {
		streams = 1
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, expires, streams, nil
}

// resolveDropFolder implements the brief's "ask where to drop the files".
func resolveDropFolder(flagVal string) (string, error) {
	def := filepath.Join(exeDir, "incoming")
	if strings.TrimSpace(flagVal) != "" {
		abs, err := filepath.Abs(flagVal)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return "", err
		}
		return abs, nil
	}
	fmt.Println()
	fmt.Printf("example: %s\n", def)
	for {
		got := ask("Drop The Files In", def)
		abs, err := filepath.Abs(got)
		if err != nil {
			fmt.Println("  cannot use that path:", err)
			continue
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			fmt.Println("  cannot create that folder:", err)
			continue
		}
		if !confirm(fmt.Sprintf("Use %s?", abs), true) {
			continue
		}
		return abs, nil
	}
}

func checkSpace(outRoot string, need int64) error {
	free, err := freeBytes(outRoot)
	if err != nil {
		say("could not check free space on %s: %v", outRoot, err)
		return nil
	}
	headroom := need + (1 << 30)
	if free < headroom {
		return fmt.Errorf("%s sits on a volume with %s free and this needs %s - pick another folder with -out", outRoot, wire.Human(free), wire.Human(headroom))
	}
	say("space check: %s free, %s needed", wire.Human(free), wire.Human(need))
	return nil
}

// reverify re-hashes what the state file claims is already on disk, so a resume
// after a crash cannot keep a truncated piece.
func (r *receiver) reverify() error {
	buf := make([]byte, copyBlock)
	var checked, dropped int64
	for _, s := range r.streams {
		f := s.file
		fs := r.state.file(f.ID)
		if fs == nil || len(fs.Done) == 0 {
			continue
		}
		if len(f.Members) > 0 {
			for _, m := range f.Members {
				want := fs.Members[m.Name]
				if want == "" {
					continue
				}
				path := r.partPath(m.Name)
				hex, err := hashWholeFile(path, m.Length, buf)
				checked++
				if err != nil || hex != want {
					fs.Members = map[string]string{}
					fs.Done = map[int64]string{}
					dropped++
					say("pack member %s did not verify, re-pulling its pack", m.Name)
					break
				}
			}
			continue
		}
		path := r.partPath(f.Name)
		st, err := os.Stat(path)
		if err != nil {
			say("%s is not on disk any more, re-pulling all %d chunks", f.Name, f.Chunks)
			fs.Done = map[int64]string{}
			continue
		}
		if st.Size() != fs.Size {
			say("%s changed size on disk (%s), starting it over", f.Name, wire.Human(st.Size()))
			fs.Done = map[int64]string{}
			continue
		}
		for _, idx := range sortedKeys(fs.Done) {
			offset, length := wire.ChunkRange(fs.Size, fs.Chunk, idx)
			hf, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, err := copyRange(h, hf, offset, length, buf)
			_ = hf.Close()
			checked++
			if err != nil || n != length || hex.EncodeToString(h.Sum(nil)) != fs.Done[idx] {
				delete(fs.Done, idx)
				dropped++
				say("%s chunk %d did not verify, will re-pull", f.Name, idx)
			}
		}
	}
	if checked > 0 {
		say("re-verified %d pieces on disk, %d need re-pulling", checked, dropped)
		if err := r.state.save(); err != nil {
			return err
		}
	}
	return nil
}

func hashWholeFile(path string, size int64, buf []byte) (string, error) {
	hf, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer hf.Close()
	st, err := hf.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() != size {
		return "", fmt.Errorf("%s is %s, expected %s", filepath.Base(path), wire.Human(st.Size()), wire.Human(size))
	}
	h := sha256.New()
	if _, err := io.CopyBuffer(h, hf, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortedKeys(m map[int64]string) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func copyRange(w io.Writer, rd io.ReaderAt, offset, length int64, buf []byte) (int64, error) {
	var done int64
	for done < length {
		want := int64(len(buf))
		if rest := length - done; rest < want {
			want = rest
		}
		n, err := rd.ReadAt(buf[:want], offset+done)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return done, werr
			}
			done += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return done, fmt.Errorf("reached end of file at %s of %s", wire.Human(done), wire.Human(length))
			}
			return done, err
		}
	}
	return done, nil
}

// runWorker keeps one data lane busy until the queue runs dry.
func (r *receiver) runWorker() error {
	c, first, _, err := openConn(r.server, "worker", r.password, "", r.pin)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := expectReply(c, first, "worker_ok"); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})

	for {
		job, ok := r.queue.next()
		if !ok || r.aborted() {
			return nil
		}
		err := r.pullChunk(c, job)
		if err == nil {
			r.queue.success()
			continue
		}
		code, text := wireCode(err)
		switch code {
		case "digest_mismatch":
			if job.Tries < 2 {
				job.Tries++
				say("chunk %d of %s hashed wrong, retrying (%d/2)", job.index, r.nameOf(job.id), job.Tries)
				if r.queue.push(job) {
					continue
				}
			}
			return fmt.Errorf("digest_mismatch: %s", text)
		case "no_lane", "gone", "sender_error", "lane_lost":
			if job.Tries < 1 && !r.aborted() {
				job.Tries++
				time.Sleep(2 * time.Second)
				if r.queue.push(job) {
					continue
				}
			}
			return fmt.Errorf("%s: %s", code, text)
		default:
			return fmt.Errorf("%s", text)
		}
	}
}

func (r *receiver) streamFor(id string) (stream, bool) {
	for _, s := range r.streams {
		if s.file.ID == id {
			return s, true
		}
	}
	return stream{}, false
}

func (r *receiver) nameOf(id string) string {
	if s, ok := r.streamFor(id); ok {
		return s.file.Name
	}
	return id
}

// pullChunk takes one chunk of one stream and writes the bytes it selected.
func (r *receiver) pullChunk(c *wire.Conn, job chunkJob) error {
	s, ok := r.streamFor(job.id)
	if !ok {
		return fmt.Errorf("bad_request: %s is not in my plan", job.id)
	}
	f := s.file
	if err := c.Send(wire.Msg{T: "get", File: job.id, Index: job.index}); err != nil {
		return fmt.Errorf("lane_lost: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(90 * time.Second))
	hdr, err := c.Recv()
	if err != nil {
		return fmt.Errorf("lane_lost: no begin frame: %w", err)
	}
	if e := hdr.AsError(); e != nil {
		return e
	}
	if hdr.T != "begin" {
		return fmt.Errorf("bad_frame: expected begin, got %q", hdr.T)
	}
	if hdr.File != job.id || hdr.Index != job.index {
		return fmt.Errorf("bad_frame: begin is for %s chunk %d", hdr.File, hdr.Index)
	}
	offset, want := wire.ChunkRange(f.Size, f.Chunk, job.index)
	if hdr.Length != want || hdr.Offset != offset {
		return fmt.Errorf("bad_frame: begin says offset %d length %d, we wanted offset %d length %d", hdr.Offset, hdr.Length, offset, want)
	}

	// Budget assumes at least half a megabyte per second per lane: generous
	// for a stalled friend link, tight enough to notice a dead relay.
	_ = c.SetDeadline(time.Now().Add(30*time.Second + time.Duration(hdr.Length>>20)*2*time.Second))

	var digest string
	var members []string
	if len(f.Members) > 0 {
		digest, members, err = r.readPack(c, s, hdr.Length)
	} else {
		digest, err = r.readPlainChunk(c, s, offset, hdr.Length)
	}
	if err != nil {
		return err
	}

	end, err := c.Recv()
	_ = c.SetDeadline(time.Now().Add(90 * time.Second))
	if err != nil {
		return fmt.Errorf("lane_lost: no end frame: %w", err)
	}
	if e := end.AsError(); e != nil {
		return e
	}
	if end.T != "end" {
		return fmt.Errorf("bad_frame: expected end, got %q", end.T)
	}
	if !strings.EqualFold(digest, end.SHA256) {
		return fmt.Errorf("digest_mismatch: %s chunk %d is %s here, sender says %s", f.Name, job.index, digest, end.SHA256)
	}
	if len(f.Members) > 0 {
		if len(end.Digests) != len(f.Members) {
			return fmt.Errorf("digest_mismatch: pack %s sent %d member hashes for %d files", f.Name, len(end.Digests), len(f.Members))
		}
		for i, m := range f.Members {
			if !strings.EqualFold(members[i], end.Digests[i]) {
				return fmt.Errorf("digest_mismatch: %s is %s here, sender says %s", m.Name, members[i], end.Digests[i])
			}
		}
	}

	atomic.AddInt64(&r.chunks, 1)
	var memberHashes map[string]string
	if len(f.Members) > 0 {
		memberHashes = map[string]string{}
		for _, name := range s.wanted {
			for i, m := range f.Members {
				if m.Name == name {
					memberHashes[name] = members[i]
				}
			}
		}
	}
	done, err := r.state.recordChunk(f, job.index, digest, memberHashes)
	if err != nil {
		return fmt.Errorf("local: cannot save progress: %w", err)
	}
	if done {
		if len(f.Members) > 0 {
			say("complete: %d files in %s", len(f.Members), f.Name)
		} else {
			say("complete: %s", f.Name)
		}
	}
	return nil
}

// readPlainChunk writes one range of a single file at its offset.
func (r *receiver) readPlainChunk(c *wire.Conn, s stream, offset, length int64) (string, error) {
	f := s.file
	out, err := r.handles.get(f.ID, r.partPath(f.Name), f.Size)
	if err != nil {
		return "", fmt.Errorf("local: %w", err)
	}
	h := sha256.New()
	dst := io.MultiWriter(&offsetWriter{f: out, off: offset}, h)
	n, err := io.CopyBuffer(dst, io.LimitReader(c.Raw(), length), make([]byte, copyBlock))
	if err != nil {
		return "", fmt.Errorf("lane_lost: payload broke: %w", err)
	}
	if n != length {
		return "", fmt.Errorf("lane_lost: short chunk, %s of %s", wire.Human(n), wire.Human(length))
	}
	atomic.AddInt64(&r.got, n)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readPack splits one packed stream across its member files. Members that
// were not selected are still hashed, because the sender hashed them too, but
// nothing is written for them.
func (r *receiver) readPack(c *wire.Conn, s stream, length int64) (string, []string, error) {
	packHash := sha256.New()
	memberHashes := make([]string, 0, len(s.file.Members))
	wanted := map[string]bool{}
	for _, n := range s.wanted {
		wanted[n] = true
	}
	buf := make([]byte, copyBlock)
	var consumed int64

	for _, m := range s.file.Members {
		h := sha256.New()
		var sinks []io.Writer
		sinks = append(sinks, h, packHash)
		var out *os.File
		if wanted[m.Name] {
			// Empty files still get their handle, so the finish step has a
			// .part to rename for every file it was told to write.
			f, err := r.handles.get("member:"+m.Name, r.partPath(m.Name), m.Length)
			if err != nil {
				return "", nil, fmt.Errorf("local: %w", err)
			}
			out = f
			sinks = append(sinks, &offsetWriter{f: f, off: 0})
		}
		done := int64(0)
		for done < m.Length {
			want := int64(len(buf))
			if rest := m.Length - done; rest < want {
				want = rest
			}
			n, err := io.ReadFull(io.LimitReader(c.Raw(), want), buf[:want])
			if n > 0 {
				for _, w := range sinks {
					if _, werr := w.Write(buf[:n]); werr != nil {
						return "", nil, fmt.Errorf("local: write failed for %s: %w", m.Name, werr)
					}
				}
				done += int64(n)
				consumed += int64(n)
				atomic.AddInt64(&r.got, int64(n))
			}
			if err != nil {
				if out != nil {
					return "", nil, fmt.Errorf("lane_lost: pack payload broke at %s: %w", m.Name, err)
				}
				return "", nil, fmt.Errorf("lane_lost: pack payload broke at %s: %w", m.Name, err)
			}
		}
		memberHashes = append(memberHashes, hex.EncodeToString(h.Sum(nil)))
	}
	if consumed != length {
		return "", nil, fmt.Errorf("lane_lost: pack delivered %s of %s", wire.Human(consumed), wire.Human(length))
	}
	return hex.EncodeToString(packHash.Sum(nil)), memberHashes, nil
}

func (r *receiver) partPath(name string) string {
	return filepath.Join(r.outRoot, filepath.FromSlash(name)) + ".part"
}

func (r *receiver) finalPath(name string) string {
	return filepath.Join(r.outRoot, filepath.FromSlash(name))
}

func (r *receiver) progress() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var last int64
	var rate float64
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
			cur := atomic.LoadInt64(&r.got)
			d := cur - last
			last = cur
			if d > 0 {
				rate = rate*0.7 + float64(d)
			}
			pct := 0.0
			if r.total > 0 {
				pct = float64(cur) / float64(r.total) * 100
			}
			eta := "-"
			if rate > (1<<20) && cur < r.total {
				eta = (time.Duration(float64(r.total-cur)/rate) * time.Second).Round(time.Second).String()
			}
			status(fmt.Sprintf("%5.1f%%  %s / %s  @ %s/s  eta %s  chunks %d",
				pct, wire.Human(cur), wire.Human(r.total), wire.Human(int64(rate)), eta, atomic.LoadInt64(&r.chunks)))
		}
	}
}

func (r *receiver) fail(err error) {
	if err == nil {
		return
	}
	if r.abort.Load() == nil {
		r.abort.Store(err)
	}
	r.stopNow()
	r.queue.abort()
}

func (r *receiver) stopNow() {
	r.stopOnce.Do(func() { close(r.stop) })
}

func (r *receiver) aborted() bool { return r.abort.Load() != nil }

func (r *receiver) collectedErrs() []error {
	if v := r.abort.Load(); v != nil {
		if err, ok := v.(error); ok {
			return []error{err}
		}
	}
	return nil
}

// keepalive holds the control connection open for the whole transfer, because
// the relay drops a control channel that has not spoken for a few minutes.
func (r *receiver) keepalive() {
	tick := time.NewTicker(45 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
			if err := r.control.Send(wire.Msg{T: "keep"}); err != nil {
				return
			}
		}
	}
}

// finish moves every completed piece into place and stamps the mtimes.
func (r *receiver) finish() error {
	r.handles.closeAll()
	var problems []string
	var entries []manifestFile
	for _, s := range r.streams {
		f := s.file
		fs := r.state.file(f.ID)
		if fs == nil || !fs.complete() {
			problems = append(problems, f.Name)
			continue
		}
		wanted := map[string]bool{}
		for _, n := range s.wanted {
			wanted[n] = true
		}
		if len(f.Members) == 0 {
			if err := r.place(f.Name, f.Mtime); err != nil {
				return err
			}
			entries = append(entries, manifestFile{
				Name: f.Name, Size: f.Size, Mtime: f.Mtime,
				Chunk: f.Chunk, Chunks: f.Chunks, Digest: r.state.chain(f.ID, f.Chunks),
			})
			continue
		}
		for _, m := range f.Members {
			if !wanted[m.Name] {
				continue
			}
			if err := r.place(m.Name, m.Mtime); err != nil {
				return err
			}
			entries = append(entries, manifestFile{
				Name: m.Name, Size: m.Length, Mtime: m.Mtime,
				Digest: r.state.member(f.ID, m.Name),
			})
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d stream(s) are still incomplete: %s", len(problems), humanList(problems))
	}
	// The receipt is the proof of what landed, and what `check` verifies later.
	if err := saveReceipt(r.outRoot, r.server, entries); err != nil {
		say("could not write the receipt: %v", err)
	}
	if err := os.Remove(r.state.path); err != nil && !os.IsNotExist(err) {
		say("left %s behind: %v", r.state.path, err)
	}
	return nil
}

func (r *receiver) place(name string, mtime int64) error {
	part := r.partPath(name)
	final := r.finalPath(name)
	if err := os.Rename(part, final); err != nil {
		if _, statErr := os.Stat(part); os.IsNotExist(statErr) {
			if _, ferr := os.Stat(final); ferr == nil {
				return nil // already in place from an earlier run
			}
			return fmt.Errorf("%s vanished before it could be moved into place", name)
		}
		_ = os.Remove(final)
		if err2 := os.Rename(part, final); err2 != nil {
			return fmt.Errorf("cannot move %s into place: %w", name, err2)
		}
	}
	if mtime > 0 {
		_ = os.Chtimes(final, time.Unix(mtime, 0), time.Unix(mtime, 0))
	}
	return nil
}

func (r *receiver) report(errs []error) error {
	clearStatus()
	fmt.Println()
	if len(errs) > 0 {
		fmt.Println("transfer did not finish:")
		for _, e := range errs {
			fmt.Println("  -", e)
		}
		fmt.Printf("\nprogress is saved in %s\n", r.state.path)
		fmt.Println("while the sender is still online, run the same command again to continue where it stopped.")
		return errs[0]
	}
	elapsed := time.Since(r.started).Round(time.Second)
	written := r.countWritten()
	fmt.Printf("done: %d files in %s (%s pulled this run) in %s\n", written, r.outRoot, wire.Human(atomic.LoadInt64(&r.got)), elapsed)
	fmt.Printf("verified: every file landed at its expected size and every chunk hash matched\n")
	if rate := float64(atomic.LoadInt64(&r.got)) / elapsed.Seconds(); elapsed > 0 && rate > 0 {
		fmt.Printf("average %s/s\n", wire.Human(int64(rate)))
	}
	fmt.Println()
	fmt.Println("per-file SHA-256 - compare these with what the sender printed:")
	for _, line := range r.digestReport() {
		fmt.Println("  " + line)
	}
	return nil
}

func (r *receiver) countWritten() int {
	n := 0
	for _, s := range r.streams {
		if len(s.file.Members) == 0 {
			n++
			continue
		}
		n += len(s.wanted)
	}
	return n
}

func (r *receiver) digestReport() []string {
	var out []string
	for _, s := range r.streams {
		f := s.file
		if len(f.Members) == 0 {
			out = append(out, fmt.Sprintf("%-10s %-40s %s", wire.Human(f.Size), f.Name, r.state.chain(f.ID, f.Chunks)))
			continue
		}
		for _, m := range f.Members {
			if !contains(s.wanted, m.Name) {
				continue
			}
			out = append(out, fmt.Sprintf("%-10s %-40s %s", wire.Human(m.Length), m.Name, r.state.member(f.ID, m.Name)))
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// wireCode pulls the relay's error code out of an error message.
func wireCode(err error) (string, string) {
	var pe *wire.Error
	if errors.As(err, &pe) {
		return pe.Code, pe.Text
	}
	msg := err.Error()
	if parts := strings.SplitN(msg, ": ", 2); len(parts) == 2 {
		return parts[0], msg
	}
	return "local", msg
}

// discardPartial deletes the .part files of the picked streams and the saved
// progress, then any folders that were created for them and are now empty.
// Finished files are never touched.
func (r *receiver) discardPartial() {
	var dirs []string
	drop := func(name string) {
		part := r.partPath(name)
		for i := 0; i < 5; i++ {
			err := os.Remove(part)
			if err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		dirs = append(dirs, filepath.Dir(part))
	}
	for _, s := range r.streams {
		if len(s.file.Members) == 0 {
			drop(s.file.Name)
			continue
		}
		for _, m := range s.file.Members {
			drop(m.Name)
		}
	}
	_ = os.Remove(r.state.path)
	for _, d := range dirs {
		for d != r.outRoot && strings.HasPrefix(d, r.outRoot) {
			if os.Remove(d) != nil { // fails while the folder still holds anything
				break
			}
			d = filepath.Dir(d)
		}
	}
}
