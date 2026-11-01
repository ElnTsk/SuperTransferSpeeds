// Package wire carries the framed JSON control protocol and the raw byte
// channels that sit on top of it between the CLI and the relay.
package wire

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// ProtoV is the wire version both sides must agree on.
	ProtoV = 3

	// MaxMsg bounds one control frame; manifests are split to stay inside it.
	MaxMsgLen = 4 << 20

	readBufSize  = 4 << 20
	writeBufSize = 1 << 20
)

// Size classes. Small ships coarse, large ships fine and parallel.
const (
	SmallMax = int64(10) << 30
	LargeMin = int64(100) << 30

	SmallChunk  = int64(64) << 20
	MediumChunk = int64(128) << 20
	LargeChunk  = int64(512) << 20

	DefaultMib = MediumChunk
)

func ClassOf(size int64) string {
	switch {
	case size >= LargeMin:
		return "large"
	case size <= SmallMax:
		return "small"
	default:
		return "medium"
	}
}

// ChunkSize scales the resume unit with the file: a 60 MB clip does not want
// the same granularity as a 120 GB disc image, and a piece that is too big
// cannot be split across lanes or re-sent cheaply when it breaks.
// An explicit session chunk overrides medium and large files.
func ChunkSize(size, sessionChunk int64) int64 {
	if size <= 0 {
		return 1
	}
	class := ClassOf(size)
	want := SmallChunk
	switch class {
	case "medium":
		want = MediumChunk
	case "large":
		want = LargeChunk
	}
	if class != "small" && sessionChunk > 0 {
		want = sessionChunk
	}
	if size < want {
		return size
	}
	return want
}

// NumChunks is how many pieces a file is cut into. An empty file still counts
// as one piece, so the sender can serve it as a zero-length payload rather than
// the relay rejecting a manifest entry with no chunks.
func NumChunks(size, chunk int64) int64 {
	if chunk <= 0 {
		chunk = DefaultMib
	}
	if size <= 0 {
		return 1
	}
	return (size + chunk - 1) / chunk
}

// ChunkRange maps a chunk index to its byte range.
func ChunkRange(size, chunk int64, index int64) (offset, length int64) {
	offset = index * chunk
	if offset >= size {
		return offset, 0
	}
	length = size - offset
	if length > chunk {
		length = chunk
	}
	return offset, length
}

// Member is one real file carried inside a packed pseudo-file.
type Member struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Mtime  int64  `json:"mtime,omitempty"`
}

// File is one manifest entry. A small-file pack is also a File: its Name is a
// synthetic @pack/ path and its bytes are the members concatenated.
type File struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Size    int64    `json:"size"`
	Mtime   int64    `json:"mtime"`
	Chunk   int64    `json:"chunk"`
	Chunks  int64    `json:"chunks"`
	Class   string   `json:"class"`
	Members []Member `json:"members,omitempty"`
	Nonce   string   `json:"nonce,omitempty"`
}

// IsPack reports whether this entry carries several files in one stream.
func (f File) IsPack() bool { return strings.HasPrefix(f.Name, "@pack/") }

// PackPrefix names the synthetic path space used by packed small files.
const PackPrefix = "@pack/"

// Msg is the single envelope for every frame. Fields are optional and read
// according to T, which keeps the protocol one type instead of twenty.
type Msg struct {
	T        string   `json:"t"`
	V        int      `json:"v,omitempty"`
	Role     string   `json:"role,omitempty"`
	Token    string   `json:"token,omitempty"`
	Name     string   `json:"name,omitempty"`
	Code     string   `json:"code,omitempty"`
	Err      string   `json:"err,omitempty"`
	Session  string   `json:"session,omitempty"`
	Pin      string   `json:"pin,omitempty"`
	Endpoint string   `json:"endpoint,omitempty"`
	Expires  int64    `json:"expires,omitempty"`
	Streams  int      `json:"streams,omitempty"`
	Chunk    int64    `json:"chunk,omitempty"`
	File     string   `json:"file,omitempty"`
	Index    int64    `json:"index,omitempty"`
	Offset   int64    `json:"offset,omitempty"`
	Length   int64    `json:"length,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Bytes    int64    `json:"bytes,omitempty"`
	Count    int64    `json:"count,omitempty"`
	Root     string   `json:"root,omitempty"`
	Files    []File   `json:"files,omitempty"`
	Digests  []string `json:"digests,omitempty"`
	Mac      string   `json:"mac,omitempty"`
	Done     bool     `json:"done,omitempty"`
}

// Conn pairs a socket with buffered readers so the framing stays in one place.
// Every byte read or written on the socket must go through r/w, otherwise a
// raw read steals the middle of a frame. One reader goroutine plus one raw
// writer goroutine is the model; Send is mutex-guarded so control frames from
// different goroutines cannot interleave mid-frame.
type Conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
	mu sync.Mutex
}

func Wrap(nc net.Conn) *Conn {
	return &Conn{
		nc: nc,
		r:  bufio.NewReaderSize(nc, readBufSize),
		w:  bufio.NewWriterSize(nc, writeBufSize),
	}
}

func (c *Conn) Net() net.Conn                 { return c.nc }
func (c *Conn) RemoteAddr() string            { return c.nc.RemoteAddr().String() }
func (c *Conn) Close() error                  { return c.nc.Close() }
func (c *Conn) Raw() io.Reader                { return c.r }
func (c *Conn) Buf() io.Writer                { return c.w }
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// Send writes one frame and flushes, so no frame can sit in the buffer behind
// a raw payload that is already waiting.
func (c *Conn) Send(m Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMsgLen {
		return fmt.Errorf("frame too large: %d bytes", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Conn) Recv() (Msg, error) {
	var m Msg
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMsgLen {
		return m, fmt.Errorf("bad frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c.r, b); err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// Flush after writing raw payload bytes into c.Buf().
func (c *Conn) Flush() error { return c.w.Flush() }

// ErrMsg builds the error frame.
func ErrMsg(code, text string) Msg { return Msg{T: "error", Code: code, Err: text} }

// Error is a typed protocol failure with a machine-readable code.
type Error struct {
	Code string
	Text string
}

func (e *Error) Error() string { return e.Code + ": " + e.Text }

// AsError turns an error frame into a typed failure, and returns nil for every
// other frame so callers can write `if e := m.AsError(); e != nil`.
func (m Msg) AsError() *Error {
	if m.T != "error" {
		return nil
	}
	return &Error{Code: m.Code, Text: m.Err}
}

// tokenAlphabet is Crockford base32 minus I, L, O and U so codes survive being
// read out loud or typed from a chat window.
const tokenAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewToken returns groups of four symbols, n symbols in total.
func NewToken(n int) (string, error) {
	if n < 8 {
		n = 8
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(tokenAlphabet[int(x)%len(tokenAlphabet)])
	}
	return sb.String(), nil
}

// NormalizeToken strips what people paste in place of a dash and uppercases
// the letters that survive.
func NormalizeToken(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r == '-', r == ' ', r == '_', r == '\n', r == '\r', r == '\t':
			sb.WriteRune('-')
		}
	}
	out := sb.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}

// PinOf is the value the client pins to trust this relay's certificate.
func PinOf(der []byte) string {
	h := sha256.Sum256(der)
	return "sha256/" + base64.StdEncoding.EncodeToString(h[:])
}

// FileDigest binds every chunk digest together so a whole file can be checked
// with one short value, without re-reading it.
func FileDigest(chunkDigests [][]byte) string {
	h := sha256.New()
	for _, d := range chunkDigests {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func HexDigest(b []byte) string { return hex.EncodeToString(b) }

// SplitForFraming groups manifest entries so each group serialises under limit
// bytes. A pack carries its member list, so the count alone says nothing about
// frame size and the sender must measure instead of guessing.
func SplitForFraming(files []File, limit int) [][]File {
	if limit <= 0 || limit > MaxMsgLen/2 {
		limit = MaxMsgLen / 2
	}
	var out [][]File
	var cur []File
	size := 0
	for i := range files {
		n := 192
		if b, err := json.Marshal(files[i]); err == nil {
			n = len(b)
		}
		if size+n > limit && len(cur) > 0 {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, files[i])
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// Human renders a byte count the way the console table shows it.
func Human(n int64) string {
	if n < 0 {
		return "-"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
