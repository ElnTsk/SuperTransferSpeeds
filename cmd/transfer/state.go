package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"transfer/internal/wire"
)

type fileState struct {
	Name     string            `json:"name"`
	Size     int64             `json:"size"`
	Chunk    int64             `json:"chunk"`
	Chunks   int64             `json:"chunks"`
	Mtime    int64             `json:"mtime"`
	Done     map[int64]string  `json:"done"`
	Members  map[string]string `json:"members,omitempty"`  // pack member -> digest
	Complete bool              `json:"complete,omitempty"` // adopted from a receipt
	Chain    string            `json:"chain,omitempty"`    // chain digest from that receipt
}

func (f *fileState) complete() bool {
	if f == nil {
		return false
	}
	if f.Complete {
		return true
	}
	return f.Chunks > 0 && int64(len(f.Done)) >= f.Chunks
}

// fileState tracks what has already landed for one stream, chunk by chunk, so
// an interrupted pull continues instead of starting over.

type dlState struct {
	Version int
	Out     string
	Updated time.Time
	Files   map[string]*fileState

	mu    sync.Mutex
	path  string
	saves int
}

const stateVersion = 2

// statePath is deliberately not keyed on the session code: the files in a drop
// folder are what matter, so a new code (new sender session, same selection)
// still resumes the pieces already on disk.
func statePath(outRoot string) string {
	return filepath.Join(outRoot, "."+strings.ToLower(appName)+"-state.json")
}

func loadDLState(outRoot string) *dlState {
	s := &dlState{Version: stateVersion, Out: outRoot, Files: map[string]*fileState{}, path: statePath(outRoot)}

	// Read the file an earlier name of the tool left behind, then keep writing
	// to the current name.
	src := s.path
	if _, err := os.Stat(src); err != nil {
		legacy := filepath.Join(outRoot, ".supertransfer-state.json")
		if _, lerr := os.Stat(legacy); lerr == nil {
			src = legacy
		}
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return s
	}
	var onDisk dlState
	if err := json.Unmarshal(b, &onDisk); err != nil {
		return s
	}
	// An old state file describes a different transport; starting clean beats
	// trying to translate a half-finished download across versions.
	if onDisk.Version != stateVersion {
		return s
	}
	if onDisk.Files == nil {
		onDisk.Files = map[string]*fileState{}
	}
	s.Files = onDisk.Files
	return s
}

// save rewrites the whole state file through a temp name; a crash mid-write
// must not cost the resume map for a 100 GB download.
func (s *dlState) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *dlState) saveLocked() error {
	s.Updated = time.Now()
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		// Windows refuses a rename onto a file that is open elsewhere.
		_ = os.Remove(s.path)
		if err2 := os.Rename(tmp, s.path); err2 != nil {
			return fmt.Errorf("write %s: %w", s.path, err2)
		}
	}
	return nil
}

// reconcile adopts the plan the sender offered now and drops any recorded
// progress that no longer matches it.
func (s *dlState) reconcile(streams []stream) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reset []string
	for _, st := range streams {
		f := st.file
		fs, ok := s.Files[f.ID]
		if ok && fs != nil {
			if fs.Size != f.Size || fs.Chunk != f.Chunk || fs.Chunks != f.Chunks || fs.Name != f.Name || !sameMembers(fs.Members, f.Members, st.wanted) {
				reset = append(reset, f.Name)
				ok = false
			}
		}
		if !ok {
			s.Files[f.ID] = &fileState{
				Name: f.Name, Size: f.Size, Chunk: f.Chunk, Chunks: f.Chunks, Mtime: f.Mtime,
				Done: map[int64]string{}, Members: map[string]string{},
			}
			continue
		}
		if fs.Done == nil {
			fs.Done = map[int64]string{}
		}
		if fs.Members == nil {
			fs.Members = map[string]string{}
		}
	}
	// Entries for files this plan does not mention are left alone: another
	// transfer into the same folder may still want them.
	sort.Strings(reset)
	return reset
}

func sameMembers(recorded map[string]string, members []wire.Member, wanted []string) bool {
	if len(members) == 0 {
		return true
	}
	for _, name := range wanted {
		if _, ok := recorded[name]; !ok {
			continue // never finished, so nothing to disagree with
		}
		found := false
		for _, m := range members {
			if m.Name == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *dlState) pending(f wire.File) []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[f.ID]
	if fs == nil {
		return allChunks(f.Chunks)
	}
	if fs.complete() {
		return nil // already on disk and matching the receipt
	}
	out := make([]int64, 0, f.Chunks)
	for i := int64(0); i < f.Chunks; i++ {
		if _, ok := fs.Done[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

func allChunks(n int64) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(i)
	}
	return out
}

// recordChunk stores one verified chunk, and for a pack the member hashes that
// came with it, then saves so a crash costs at most a few pieces.
func (s *dlState) recordChunk(f wire.File, index int64, digest string, memberHashes map[string]string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[f.ID]
	if fs == nil {
		fs = &fileState{Name: f.Name, Size: f.Size, Chunk: f.Chunk, Chunks: f.Chunks, Mtime: f.Mtime, Done: map[int64]string{}, Members: map[string]string{}}
		s.Files[f.ID] = fs
	}
	if fs.Done == nil {
		fs.Done = map[int64]string{}
	}
	fs.Done[index] = digest
	for name, h := range memberHashes {
		if fs.Members == nil {
			fs.Members = map[string]string{}
		}
		fs.Members[name] = h
	}
	s.saves++
	done := int64(len(fs.Done)) >= fs.Chunks
	if done || s.saves%4 == 0 {
		return done, s.saveLocked()
	}
	return done, nil
}

func (s *dlState) file(id string) *fileState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Files[id]
}

func (s *dlState) chain(id string, chunks int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[id]
	if fs == nil {
		return "incomplete"
	}
	if fs.Chain != "" {
		return fs.Chain // adopted from a receipt, already verified once
	}
	if int64(len(fs.Done)) < chunks {
		return "incomplete"
	}
	raw := make([][]byte, 0, chunks)
	for i := int64(0); i < chunks; i++ {
		b, err := hex.DecodeString(fs.Done[i])
		if err != nil {
			return "unreadable digest"
		}
		raw = append(raw, b)
	}
	return wire.FileDigest(raw)
}

func (s *dlState) member(id, name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[id]
	if fs == nil {
		return "unknown"
	}
	if d, ok := fs.Members[name]; ok {
		return d
	}
	return "not written"
}

// chunkJob is one unit of work on the receive side.
type chunkJob struct {
	id    string
	index int64
	Tries int
}

// workQueue is the pending chunk list. It cannot be a closed channel, because
// a failed chunk has to go back in line while the other lanes keep working.
type workQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []chunkJob
	pending int
	closed  bool
}

func newWorkQueue() *workQueue {
	q := &workQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push accepts a chunk only while work is still outstanding, so a late retry
// cannot resurrect a queue that has already been drained.
func (q *workQueue) push(j chunkJob) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.items = append(q.items, j)
	q.pending++
	q.cond.Signal()
	return true
}

func (q *workQueue) next() (chunkJob, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed || len(q.items) == 0 {
		return chunkJob{}, false
	}
	j := q.items[0]
	q.items = q.items[1:]
	return j, true
}

func (q *workQueue) success() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending--
	if q.pending <= 0 {
		q.pending = 0
		q.closed = true
		q.items = nil
		q.cond.Broadcast()
	}
}

func (q *workQueue) abort() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.pending = 0
	q.items = nil
	q.cond.Broadcast()
}

// offsetWriter lets io.MultiWriter push a chunk straight into the file at its
// own offset while the same bytes feed the hasher.
type offsetWriter struct {
	f   *os.File
	off int64
}

func (w *offsetWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	w.off += int64(n)
	return n, err
}

// codeRe matches the four-group session code wherever it appears in a paste.
var codeRe = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}`)

// parsePaste accepts either a bare code or the whole desktop txt and pulls out
// what it can.
func parsePaste(text string) (code, endpoint, pin string) {
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		key, val, found := strings.Cut(l, ":")
		if !found {
			key, val, found = strings.Cut(l, "=")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if found {
			switch key {
			case "password", "pass":
				code = val
			case "code", "token":
				// Older handoff blocks called it a code; take it as-is.
				code = strings.TrimSpace(val)
			case "endpoint", "server", "relay":
				endpoint = val
			case "pin", "cert", "fingerprint":
				pin = val
			}
		}
	}
	if code == "" {
		if m := codeRe.FindString(strings.ToUpper(text)); m != "" {
			code = m
		}
	}
	return code, endpoint, pin
}

// readPaste asks for the code, tolerating a whole block being pasted in.
// readPaste takes either a bare password or a whole handoff block. A typed
// password is used immediately; a block is read until a blank line.
// isRuleLine reports a dashed or equals separator, the top of a handoff block.
func isRuleLine(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '-' && r != '=' && r != ' ' {
			return false
		}
	}
	return true
}

// readPaste takes either a bare password or a whole handoff block. The bool
// says which one it got, because a bare password is a value, not something to
// re-parse for keys.
func readPaste() (value string, bare bool, err error) {
	fmt.Print("password (or paste the block they sent you): ")
	line, err := stdin.ReadString('\n')
	first := strings.TrimSpace(line)
	if first == "" {
		return "", false, fmt.Errorf("nothing entered")
	}
	lower := strings.ToLower(first)
	// A block can start with the dashed rule, the banner, or a key line. Only
	// a plain single value is taken as the password itself.
	looksLikeBlock := isRuleLine(first) ||
		strings.Contains(lower, "connected") && strings.Contains(lower, "strs") ||
		((strings.Contains(lower, ":") || strings.Contains(lower, "=")) &&
			(strings.Contains(lower, "endpoint") || strings.Contains(lower, "pin") ||
				strings.Contains(lower, "password") || strings.Contains(lower, "code")))
	if !looksLikeBlock {
		return first, true, nil
	}

	var sb strings.Builder
	sb.WriteString(line)
	for {
		l, rerr := stdin.ReadString('\n')
		sb.WriteString(l)
		if strings.TrimSpace(l) == "" || rerr != nil {
			break
		}
	}
	return sb.String(), false, nil
}

func humanList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	if len(items) <= 6 {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(items[:6], ", "), len(items)-6)
}

// adoptFile marks a file already on disk as complete, using the digest from the
// receipt it was verified against.
func (s *dlState) adoptFile(f wire.File, chain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[f.ID]
	if fs == nil {
		fs = &fileState{Name: f.Name, Size: f.Size, Chunk: f.Chunk, Chunks: f.Chunks, Mtime: f.Mtime}
		s.Files[f.ID] = fs
	}
	fs.Complete = true
	fs.Chain = chain
}

// adoptPack does the same for a packed stream, carrying the member digests over
// so a later receipt is still meaningful.
func (s *dlState) adoptPack(f wire.File, digests map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.Files[f.ID]
	if fs == nil {
		fs = &fileState{Name: f.Name, Size: f.Size, Chunk: f.Chunk, Chunks: f.Chunks, Mtime: f.Mtime}
		s.Files[f.ID] = fs
	}
	fs.Complete = true
	if fs.Members == nil {
		fs.Members = map[string]string{}
	}
	for name, d := range digests {
		fs.Members[name] = d
	}
}
