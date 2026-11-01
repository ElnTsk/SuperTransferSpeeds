package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"transfer/internal/wire"
)

// manifestFile is one real file as it should exist on disk. Chunked files store
// a digest chain (cheap to recompute in pieces); packed members store the whole
// file's SHA-256 because that is what the sender verified.
type manifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Mtime  int64  `json:"mtime"`
	Chunk  int64  `json:"chunk,omitempty"`
	Chunks int64  `json:"chunks,omitempty"`
	Digest string `json:"digest"`
}

type receipt struct {
	Version int            `json:"version"`
	Created time.Time      `json:"created"`
	Source  string         `json:"source,omitempty"`
	Files   []manifestFile `json:"files"`
}

const receiptName = ".strs-receipt.json"

func receiptPath(root string) string { return filepath.Join(root, receiptName) }

func saveReceipt(root, source string, files []manifestFile) error {
	r := receipt{Version: 1, Created: time.Now(), Source: source, Files: files}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Name < r.Files[j].Name })
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := receiptPath(root) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, receiptPath(root)); err != nil {
		_ = os.Remove(receiptPath(root))
		return os.Rename(tmp, receiptPath(root))
	}
	return nil
}

func loadReceipt(root string) (*receipt, error) {
	b, err := os.ReadFile(receiptPath(root))
	if err != nil {
		return nil, err
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// checkOne recomputes a file's fingerprint and compares it with the receipt.
func checkOne(root string, mf manifestFile) error {
	full := filepath.Join(root, filepath.FromSlash(mf.Name))
	st, err := os.Stat(full)
	if err != nil {
		return fmt.Errorf("missing")
	}
	if st.Size() != mf.Size {
		return fmt.Errorf("size is %s, expected %s", wire.Human(st.Size()), wire.Human(mf.Size))
	}
	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()

	if mf.Chunk <= 0 || mf.Chunks <= 0 {
		h := sha256.New()
		if _, err := io.CopyBuffer(h, f, make([]byte, 4<<20)); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, mf.Digest) {
			return fmt.Errorf("hash does not match")
		}
		return nil
	}

	buf := make([]byte, 4<<20)
	raw := make([][]byte, 0, mf.Chunks)
	for i := int64(0); i < mf.Chunks; i++ {
		offset, length := wire.ChunkRange(mf.Size, mf.Chunk, i)
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		h := sha256.New()
		if length > 0 {
			if _, err := io.CopyBuffer(h, io.LimitReader(f, length), buf); err != nil {
				return err
			}
		}
		raw = append(raw, h.Sum(nil))
	}
	if got := wire.FileDigest(raw); !strings.EqualFold(got, mf.Digest) {
		return fmt.Errorf("digest chain does not match")
	}
	return nil
}

// cmdCheck verifies a finished drop folder against the receipt written when the
// transfer completed. That receipt is the only proof of what the files should
// contain, so it is required.
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", "", "folder to verify (default: this exe's incoming folder)")
	quiet := fs.Bool("quiet", false, "only print problems")
	fs.Parse(args)

	root := strings.TrimSpace(*dir)
	if root == "" {
		root = filepath.Join(exeDir, "incoming")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rc, err := loadReceipt(abs)
	if err != nil {
		return fmt.Errorf("no receipt in %s - it is written when a transfer finishes", abs)
	}

	fmt.Printf("%s\n", banner())
	fmt.Printf("checking %d files in %s (received %s)\n\n", len(rc.Files), abs, rc.Created.Format("2006-01-02 15:04"))

	var ok, bad int
	var failed []string
	var checked int64
	for _, mf := range rc.Files {
		if err := checkOne(abs, mf); err != nil {
			bad++
			failed = append(failed, fmt.Sprintf("%s: %v", mf.Name, err))
			fmt.Printf("  BAD   %-56s %v\n", mf.Name, err)
			continue
		}
		ok++
		checked += mf.Size
		if !*quiet && ok <= 20 {
			fmt.Printf("  ok    %s\n", mf.Name)
		}
	}
	if ok > 20 && !*quiet {
		fmt.Printf("  ... %d more verified\n", ok-20)
	}

	fmt.Printf("\n%d verified (%s), %d failed\n", ok, wire.Human(checked), bad)
	if bad > 0 {
		for _, f := range failed {
			fmt.Println("  -", f)
		}
		return errors.New("integrity check failed")
	}
	return nil
}

// packDigests pulls the member digests a receipt already holds.
func packDigests(byName map[string]manifestFile, wanted []string) map[string]string {
	out := map[string]string{}
	for _, n := range wanted {
		if mf, ok := byName[n]; ok && mf.Digest != "" {
			out[n] = mf.Digest
		}
	}
	return out
}

// sameFile reports whether what is on disk still looks like what was received:
// same length, and a modification time the receipt recognises. Content damage
// that keeps the size (and a forged mtime) is what `check` is for.
func sameFile(path string, size, mtime int64) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() != size {
		return false
	}
	if mtime <= 0 {
		return true
	}
	d := st.ModTime().Unix() - mtime
	return d >= -2 && d <= 2
}

func (r *receiver) adoptExisting() int {
	rc, err := loadReceipt(r.outRoot)
	if err != nil {
		return 0
	}
	byName := make(map[string]manifestFile, len(rc.Files))
	for _, mf := range rc.Files {
		byName[mf.Name] = mf
	}

	adopted := 0
	for _, s := range r.streams {
		f := s.file
		if len(f.Members) > 0 {
			all := true
			for _, m := range f.Members {
				mf, ok := byName[m.Name]
				if !ok || !sameFile(r.finalPath(m.Name), mf.Size, mf.Mtime) {
					all = false
					break
				}
			}
			if all {
				r.state.adoptPack(f, packDigests(byName, s.wanted))
				adopted += len(s.wanted)
			}
			continue
		}
		mf, ok := byName[f.Name]
		if !ok || !sameFile(r.finalPath(f.Name), mf.Size, mf.Mtime) {
			continue
		}
		r.state.adoptFile(f, mf.Digest)
		adopted++
	}
	return adopted
}
