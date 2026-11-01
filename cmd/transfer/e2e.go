package main

// End-to-end encryption between sender and receiver.
//
// The relay is only a go-between and must not be able to read or alter what it
// carries, so the password never reaches it. Both ends stretch the password
// once (PBKDF2) and split the result into two unrelated keys:
//
//	auth - sent to the relay in place of the password, to find the session
//	enc  - stays on this machine and protects the file data
//
// Every file (or small-file pack) gets its own random nonce in the manifest.
// The file key and a MAC key are derived from enc and that nonce, the bytes are
// encrypted with AES-256-CTR (same length in and out, so the relay can still
// splice a known number of bytes), and each chunk's checksum is signed so the
// relay cannot swap in data of its own.
//
// What the relay can still see: file names, sizes, timing and the receiver's
// address. Anyone who guesses the password can derive the keys, so the
// protection is only as strong as the password: use a long one.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	kdfIterations = 600_000
	kdfSalt       = "STRS-v3-e2e"
)

type masterKeys struct {
	auth []byte
	enc  []byte
}

var (
	keyMu    sync.Mutex
	keyCache = map[string]*masterKeys{}
)

func hmacOf(key []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, key)
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(p))
	}
	return m.Sum(nil)
}

// keysFor stretches a password once per run; the receiver opens many
// connections and each one needs the token.
func keysFor(password string) *masterKeys {
	password = strings.TrimSpace(password)
	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok := keyCache[password]; ok {
		return k
	}
	master, err := pbkdf2.Key(sha256.New, password, []byte(kdfSalt), kdfIterations, 32)
	if err != nil {
		panic("cannot derive keys: " + err.Error())
	}
	k := &masterKeys{auth: hmacOf(master, "auth"), enc: hmacOf(master, "enc")}
	keyCache[password] = k
	return k
}

// wireToken is what the relay sees instead of the password.
func wireToken(password string) string {
	return hex.EncodeToString(keysFor(password).auth)
}

// newNonce makes the per-file random value that goes in the manifest.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("no randomness available: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// fileCrypto holds the keys for one manifest entry.
type fileCrypto struct {
	block  cipher.Block
	macKey []byte
}

func fileCryptoFor(password, nonceHex string) (*fileCrypto, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 16 {
		return nil, fmt.Errorf("the manifest has no valid encryption nonce (is the other side an older STRS?)")
	}
	mk := keysFor(password)
	block, err := aes.NewCipher(hmacOf(mk.enc, "file", string(nonce)))
	if err != nil {
		return nil, err
	}
	return &fileCrypto{block: block, macKey: hmacOf(mk.enc, "mac", string(nonce))}, nil
}

// stream returns the keystream positioned at a byte offset, which must be a
// multiple of 16. Chunk offsets always are.
func (fc *fileCrypto) stream(offset int64) cipher.Stream {
	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint64(iv[8:], uint64(offset/aes.BlockSize))
	return cipher.NewCTR(fc.block, iv)
}

// mac signs what the sender claims about one chunk.
func (fc *fileCrypto) mac(name string, index, length int64, digest string) string {
	m := hmac.New(sha256.New, fc.macKey)
	fmt.Fprintf(m, "chunk\x00%s\x00%d\x00%d\x00%s", name, index, length, strings.ToLower(digest))
	return hex.EncodeToString(m.Sum(nil))
}

func (fc *fileCrypto) verify(name string, index, length int64, digest, got string) bool {
	want := fc.mac(name, index, length, digest)
	return hmac.Equal([]byte(want), []byte(strings.ToLower(strings.TrimSpace(got))))
}

// decryptWriter decrypts whatever is written through it before passing it on,
// without touching the caller's buffer.
type decryptWriter struct {
	w   io.Writer
	s   cipher.Stream
	buf []byte
}

func (d *decryptWriter) Write(p []byte) (int, error) {
	if cap(d.buf) < len(p) {
		d.buf = make([]byte, len(p))
	}
	b := d.buf[:len(p)]
	d.s.XORKeyStream(b, p)
	n, err := d.w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}
