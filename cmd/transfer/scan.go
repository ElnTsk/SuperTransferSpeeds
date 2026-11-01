package main

import (
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"transfer/internal/wire"
)

// item is one candidate file on the sending side.
type item struct {
	rel  string
	abs  string
	size int64
	mod  time.Time
}

// row is one line of the picker. A directory row stands for every file under
// it, so picking `games/` takes the whole tree beneath it.
type row struct {
	label  string
	dir    bool
	prefix string // directory rows: slash-separated prefix with trailing /
	size   int64
	count  int
	class  string
	pieces string
	file   int // file rows: index into the flat list, -1 for directories
}

// piecePlan describes how one file will actually be cut up, so both sides can
// see the resume granularity before committing to a 120 GB transfer.
func piecePlan(size int64) (string, string) {
	class := wire.ClassOf(size)
	chunk := wire.ChunkSize(size, appCfg.Chunk)
	n := wire.NumChunks(size, chunk)
	return class, fmt.Sprintf("%d x %s", n, wire.Human(chunk))
}

func executableDir() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

// ourOwn covers the files this tool writes, so a scan of the tool folder never
// offers up its own exe, config, or half-finished pieces. The old `transfer`
// names stay in the list so leftovers from earlier builds are not offered.
func ourOwn(base string) bool {
	b := strings.ToLower(base)
	switch {
	case b == "strs.exe", b == "strs", b == "strs-linux", b == "strs-relay.exe", b == "strs-relay",
		b == "supertransfer.exe", b == "supertransfer", b == "supertransfer-linux",
		b == "transfer.exe", b == "transfer", b == "transfer-linux", b == "transferserver":
		return true
	case b == "strs.cfg", b == "supertransfer.cfg", b == "transfer.cfg":
		return true
	case strings.HasPrefix(b, ".strs-") && strings.HasSuffix(b, ".json"):
		return true
	case strings.HasPrefix(b, ".supertransfer-") && strings.HasSuffix(b, ".json"):
		return true
	case strings.HasPrefix(b, ".transfer-") && strings.HasSuffix(b, ".json"):
		return true
	case strings.HasSuffix(b, ".part"):
		return true
	}
	return false
}

func skipDir(name string) bool {
	n := strings.ToLower(name)
	return n == "$recycle.bin" || n == "system volume information" || n == "pagefile.sys"
}

func matchesAny(patterns []string, rel, base string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lp, lbase, lrel := strings.ToLower(p), strings.ToLower(base), strings.ToLower(filepath.ToSlash(rel))
		if !strings.Contains(lp, `\`) && !strings.Contains(lp, "/") {
			if ok, _ := filepath.Match(lp, lbase); ok {
				return true
			}
			if strings.HasSuffix(lp, "*") && strings.HasPrefix(lbase, strings.TrimSuffix(lp, "*")) {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(lp, lrel); ok {
			return true
		}
		if strings.Contains(lrel, strings.Trim(lp, "*")) {
			return true
		}
	}
	return false
}

// scanFolder walks root. Everything is offered by default - zero byte files,
// hidden files, unusual extensions - because "what is in this folder" should
// not silently depend on what the tool guesses is interesting.
func scanFolder(root string, excludes []string, recursive bool) ([]item, error) {
	root = filepath.Clean(root)
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot read folder %s: %w", root, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is a file, not a folder", root)
	}

	var out []item
	skipped := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			skipped++
			return nil
		}
		if path == root {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			if !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if ourOwn(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		if matchesAny(excludes, rel, d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			skipped++
			return nil
		}
		out = append(out, item{rel: rel, abs: path, size: info.Size(), mod: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		say("%d entries could not be read and were left out", skipped)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// hashID is stable for a path, so a resume after a re-selection still lines up
// with the state file.
func hashID(rel string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(filepath.ToSlash(rel))))
	return strconv.FormatUint(h.Sum64(), 16)
}

// planFiles turns scanned files into manifest entries at the size class's
// chunk granularity. Packing happens later, on what was actually picked.
func planFiles(items []item, sessionChunk int64) []wire.File {
	files := make([]wire.File, 0, len(items))
	for _, it := range items {
		chunk := wire.ChunkSize(it.size, sessionChunk)
		files = append(files, wire.File{
			ID:     hashID(it.rel),
			Name:   filepath.ToSlash(it.rel),
			Size:   it.size,
			Mtime:  it.mod.Unix(),
			Chunk:  chunk,
			Chunks: wire.NumChunks(it.size, chunk),
			Class:  wire.ClassOf(it.size),
		})
	}
	return files
}

// PackLimit caps one packed stream, so re-pulling after a break costs at most
// this much work. PackMembers caps the member list, which keeps a folder of
// one-byte files from building a manifest entry nobody can frame.
const (
	PackLimit   = int64(64) << 20
	PackMembers = 512
)

// packSmallFiles folds runs of small files into single manifest entries. Each
// one costs the relay one round-trip, so a folder of four thousand 8 KiB files
// goes from four thousand handshakes to a handful of 64 MiB streams.
func packSmallFiles(files []wire.File, threshold int64) []wire.File {
	if threshold <= 0 {
		return files
	}
	out := make([]wire.File, 0, len(files))
	var (
		run     []wire.File
		runSize int64
	)
	flush := func() {
		if len(run) == 0 {
			return
		}
		if len(run) == 1 {
			out = append(out, run[0])
		} else {
			out = append(out, makePack(run))
		}
		run, runSize = nil, 0
	}
	for _, f := range files {
		if f.Size <= threshold {
			if runSize+f.Size > PackLimit || len(run) >= PackMembers {
				flush()
			}
			run = append(run, f)
			runSize += f.Size
			if runSize >= PackLimit || len(run) >= PackMembers {
				flush()
			}
			continue
		}
		flush()
		out = append(out, f)
	}
	flush()
	return out
}

func makePack(members []wire.File) wire.File {
	var total int64
	for _, m := range members {
		total += m.Size
	}
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}
	p := wire.File{
		ID:     "pack-" + hashID(strings.Join(names, "\x00")),
		Name:   wire.PackPrefix + hashID(strings.Join(names, "\x00")),
		Size:   total,
		Chunk:  total,
		Chunks: 1,
		Class:  "pack",
	}
	// Empty members can no longer reach here, but never advertise a zero chunk.
	if p.Chunk <= 0 {
		p.Chunk = 1
	}
	var off int64
	for _, m := range members {
		p.Members = append(p.Members, wire.Member{Name: m.Name, Offset: off, Length: m.Size, Mtime: m.Mtime})
		off += m.Size
	}
	return p
}

// buildRows turns a flat sorted file list into a tree view with one row per
// directory and one per file.
func buildRows(names []string, sizes []int64) []row {
	dirSize := map[string]int64{}
	dirCount := map[string]int{}
	for i, n := range names {
		parts := strings.Split(n, "/")
		for d := 1; d < len(parts); d++ {
			p := strings.Join(parts[:d], "/") + "/"
			dirSize[p] += sizes[i]
			dirCount[p]++
		}
	}

	var rows []row
	seen := map[string]bool{}
	for i, n := range names {
		parts := strings.Split(n, "/")
		for d := 1; d < len(parts); d++ {
			p := strings.Join(parts[:d], "/") + "/"
			if seen[p] {
				continue
			}
			seen[p] = true
			rows = append(rows, row{
				label:  strings.Repeat("  ", d-1) + parts[d-1] + "/",
				dir:    true,
				prefix: p,
				size:   dirSize[p],
				count:  dirCount[p],
				file:   -1,
			})
		}
		rows = append(rows, row{
			label: strings.Repeat("  ", len(parts)-1) + parts[len(parts)-1],
			size:  sizes[i],
			count: 1,
			file:  i,
		})
		rows[len(rows)-1].class, rows[len(rows)-1].pieces = piecePlan(sizes[i])
	}
	return rows
}

// expand turns picked row numbers into the file indexes they cover.
func (r row) expand(names []string) []int {
	if !r.dir {
		return []int{r.file}
	}
	var out []int
	for i, n := range names {
		if strings.HasPrefix(n, r.prefix) {
			out = append(out, i)
		}
	}
	return out
}

func renderRows(rows []row, show int) {
	tw := tabwriter.NewWriter(stdout(), 0, 0, 2, ' ', 0)
	fmt.Fprint(tw, "     SIZE      FILES  KIND     CLASS   PIECES              NAME\n")
	shown := len(rows)
	if show > 0 && show < shown {
		shown = show
	}
	for i, r := range rows[:shown] {
		kind, class, pieces := "file", r.class, r.pieces
		if r.dir {
			kind, class, pieces = "folder", "-", "-"
		}
		fmt.Fprintf(tw, "%3d %10s  %5d  %-7s  %-6s  %-18s  %s\n", i+1, wire.Human(r.size), r.count, kind, class, pieces, r.label)
	}
	_ = tw.Flush()
	if shown < len(rows) {
		fmt.Printf("   ... %d more rows, use -show 0 to list them all\n", len(rows)-shown)
	}
	var total int64
	files := 0
	dirs := 0
	for _, r := range rows {
		if r.dir {
			dirs++
			continue
		}
		files++
		total += r.size
	}
	fmt.Printf("   %d files (%d folders) totalling %s\n", files, dirs, wire.Human(total))
}

// parseSelection turns "1,4,7-9", "all" or "none" into indexes over n rows.
func parseSelection(spec string, n int) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "all", "a", "*":
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out, nil
	case "none", "n":
		return nil, nil
	}
	var picked []int
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, found := strings.Cut(part, "-")
		if !found {
			i, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad entry %q", part)
			}
			if i < 1 || i > n {
				return nil, fmt.Errorf("%d is outside 1-%d", i, n)
			}
			if !seen[i-1] {
				seen[i-1] = true
				picked = append(picked, i-1)
			}
			continue
		}
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("bad range %q", part)
		}
		b, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("bad range %q", part)
		}
		if a < 1 || b > n || a > b {
			return nil, fmt.Errorf("range %q is outside 1-%d", part, n)
		}
		for i := a; i <= b; i++ {
			if !seen[i-1] {
				seen[i-1] = true
				picked = append(picked, i-1)
			}
		}
	}
	sort.Ints(picked)
	return picked, nil
}

// chooseFiles shows the tree and returns the picked manifest entries. Picking
// a folder row takes every file under it.
func chooseFiles(prompt string, files []wire.File, all bool, show int) ([]wire.File, error) {
	if len(files) == 0 {
		return nil, errors.New("nothing to pick from")
	}
	if all {
		return files, nil
	}
	names := make([]string, len(files))
	sizes := make([]int64, len(files))
	for i, f := range files {
		names[i] = f.Name
		sizes[i] = f.Size
	}
	rows := buildRows(names, sizes)
	renderRows(rows, show)

	for {
		spec := ask(prompt, "all")
		picked, err := parseSelection(spec, len(rows))
		if err != nil {
			fmt.Println("  ", err)
			continue
		}
		taken := map[int]bool{}
		for _, r := range picked {
			for _, i := range rows[r].expand(names) {
				taken[i] = true
			}
		}
		if len(taken) == 0 {
			fmt.Println("   nothing selected - type all, or numbers like 1,4,7-9, or q to stop")
			if strings.EqualFold(strings.TrimSpace(spec), "q") {
				return nil, errors.New("cancelled")
			}
			continue
		}
		out := make([]wire.File, 0, len(taken))
		for i := 0; i < len(files); i++ {
			if taken[i] {
				out = append(out, files[i])
			}
		}
		return out, nil
	}
}

func cmdScan(args []string) error {
	fs2 := flag.NewFlagSet("scan", flag.ExitOnError)
	dir := fs2.String("dir", "", "folder to look in (default: this exe's folder)")
	flat := fs2.Bool("flat", false, "do not recurse, list this folder only")
	exc := fs2.String("exclude", "", "comma separated name patterns to skip")
	show := fs2.Int("show", 400, "rows to list (0 for all)")
	fs2.Parse(args)

	root, err := resolveDir(*dir)
	if err != nil {
		return err
	}
	items, err := scanFolder(root, splitList(*exc), !*flat)
	if err != nil {
		return err
	}
	files := planFiles(items, appCfg.Chunk)
	fmt.Printf("%s\n", root)
	names := make([]string, len(files))
	sizes := make([]int64, len(files))
	for i, f := range files {
		names[i], sizes[i] = f.Name, f.Size
	}
	renderRows(buildRows(names, sizes), *show)
	return nil
}

func cmdInfo(args []string) error {
	fmt.Println(banner())
	fmt.Println("exe folder  ", exeDir)
	fmt.Println("config file ", cfgPath)
	fmt.Println("resolved server:", appCfg.Server)
	if appCfg.Chunk > 0 {
		fmt.Println("chunk        ", wire.Human(appCfg.Chunk), "(forced)")
	} else {
		fmt.Println("chunk        ", "by size class: 64 MiB small, 128 MiB medium, 512 MiB large")
	}
	fmt.Println("streams     ", appCfg.Streams)
	fmt.Println("pack files under", wire.Human(appCfg.Pack), "into one stream")
	if p, err := pinStorePath(); err == nil {
		fmt.Println("pin cache   ", p)
		for host, pin := range loadPins() {
			fmt.Printf("   %-40s %s\n", host, pin)
		}
	}
	return nil
}

func resolveDir(flagVal string) (string, error) {
	if strings.TrimSpace(flagVal) != "" {
		abs, err := filepath.Abs(flagVal)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	// The brief: the tool looks through the folder it lives in.
	return filepath.Abs(exeDir)
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func absFromRel(root, rel string) string {
	return filepath.Join(root, filepath.FromSlash(rel))
}
