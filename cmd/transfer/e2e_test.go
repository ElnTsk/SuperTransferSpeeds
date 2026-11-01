package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestWireTokenIsNotThePassword(t *testing.T) {
	tok := wireToken("correct horse battery")
	if tok == "correct horse battery" || len(tok) != 64 {
		t.Fatalf("token should be 64 hex chars and differ from the password, got %q", tok)
	}
	if tok != wireToken("  correct horse battery  ") {
		t.Fatal("surrounding spaces must not change the token")
	}
	if tok == wireToken("correct horse batterz") {
		t.Fatal("different passwords gave the same token")
	}
}

func TestAuthTokenDoesNotRevealTheKey(t *testing.T) {
	mk := keysFor("correct horse battery")
	if bytes.Equal(mk.auth, mk.enc) {
		t.Fatal("auth and enc keys must differ")
	}
}

func TestChunksDecryptAtTheirOffsets(t *testing.T) {
	fc, err := fileCryptoFor("correct horse battery", newNonce())
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 5<<20)
	rand.Read(plain)
	whole := make([]byte, len(plain))
	fc.stream(0).XORKeyStream(whole, plain)
	if bytes.Equal(whole, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	// a middle chunk encrypted on its own must match the same bytes of the whole
	const off, n = 1 << 20, 2 << 20
	part := make([]byte, n)
	fc.stream(off).XORKeyStream(part, plain[off:off+n])
	if !bytes.Equal(part, whole[off:off+n]) {
		t.Fatal("a chunk encrypted at its offset differs from the same range of the whole file")
	}

	// and it round-trips through the writer the receiver uses
	var out bytes.Buffer
	dw := &decryptWriter{w: &out, s: fc.stream(off)}
	if _, err := io.Copy(dw, bytes.NewReader(part)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), plain[off:off+n]) {
		t.Fatal("decryptWriter did not restore the plaintext")
	}
}

func TestEachFileGetsItsOwnKeystream(t *testing.T) {
	a, _ := fileCryptoFor("correct horse battery", newNonce())
	b, _ := fileCryptoFor("correct horse battery", newNonce())
	plain := make([]byte, 4096)
	ca, cb := make([]byte, len(plain)), make([]byte, len(plain))
	a.stream(0).XORKeyStream(ca, plain)
	b.stream(0).XORKeyStream(cb, plain)
	if bytes.Equal(ca, cb) {
		t.Fatal("two files with different nonces produced the same keystream")
	}
}

func TestWrongPasswordCannotDecrypt(t *testing.T) {
	nonce := newNonce()
	good, _ := fileCryptoFor("correct horse battery", nonce)
	bad, _ := fileCryptoFor("correct horse batterz", nonce)
	plain := []byte("a secret that should stay secret, long enough to compare")
	ct := make([]byte, len(plain))
	good.stream(0).XORKeyStream(ct, plain)
	got := make([]byte, len(ct))
	bad.stream(0).XORKeyStream(got, ct)
	if bytes.Equal(got, plain) {
		t.Fatal("a wrong password decrypted the data")
	}
}

func TestMacBindsEveryField(t *testing.T) {
	nonce := newNonce()
	fc, _ := fileCryptoFor("correct horse battery", nonce)
	d := "ab" + string(bytes.Repeat([]byte("0"), 62))
	mac := fc.mac("docs/a.txt", 3, 1024, d)
	if !fc.verify("docs/a.txt", 3, 1024, d, mac) {
		t.Fatal("a correct mac was rejected")
	}
	for name, ok := range map[string]bool{
		"name":   fc.verify("docs/b.txt", 3, 1024, d, mac),
		"index":  fc.verify("docs/a.txt", 4, 1024, d, mac),
		"length": fc.verify("docs/a.txt", 3, 1025, d, mac),
		"digest": fc.verify("docs/a.txt", 3, 1024, "cd"+d[2:], mac),
		"empty":  fc.verify("docs/a.txt", 3, 1024, d, ""),
	} {
		if ok {
			t.Fatalf("a changed %s was accepted", name)
		}
	}
	other, _ := fileCryptoFor("correct horse battery", newNonce())
	if other.verify("docs/a.txt", 3, 1024, d, mac) {
		t.Fatal("a mac from a different file's key was accepted")
	}
	wrong, _ := fileCryptoFor("correct horse batterz", nonce)
	if wrong.verify("docs/a.txt", 3, 1024, d, mac) {
		t.Fatal("a mac was accepted under the wrong password")
	}
}

func TestMissingNonceIsRefused(t *testing.T) {
	if _, err := fileCryptoFor("correct horse battery", ""); err == nil {
		t.Fatal("an empty nonce must be refused, it means the peer is an older version")
	}
}
