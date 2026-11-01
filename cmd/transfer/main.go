package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"transfer/internal/wire"
)

const (
	version  = "1.0.1"
	appName  = "STRS"
	fullName = "SuperTransferSpeeds"
)

// banner is the one-line identity every command prints.
func banner() string {
	return appName + " " + version + " (" + fullName + ")"
}

// cfg is whatever the tool reads from its config file next to the exe.
type cfg struct {
	Server     string `json:"server"`
	Chunk      int64  `json:"chunk"`
	Streams    int    `json:"streams"`
	Pack       int64  `json:"pack"`
	PublicPort int    `json:"public_port"`
	Password   string `json:"password"`
}

var (
	stdin   = bufio.NewReader(os.Stdin)
	outMu   sync.Mutex
	exeDir  string
	cfgPath string
	appCfg  cfg
)

func main() {
	dir, err := executableDir()
	if err != nil {
		dir = "."
	}
	exeDir = dir
	cfgPath = configPath()
	appCfg = loadCfg()

	if len(os.Args) < 2 {
		// Double-click: report the relay, then offer the three jobs.
		showRelayBanner(appCfg.Server)
		err := runMenu()
		if err != nil && !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "\nerror:", err)
		}
		pause()
		if err != nil {
			os.Exit(1)
		}
		return
	}

	switch cmd := os.Args[1]; cmd {
	case "send":
		err = cmdSend(os.Args[2:])
	case "scan", "list":
		err = cmdScan(os.Args[2:])
	case "receive", "recv":
		err = cmdReceive(os.Args[2:])
	case "friend":
		err = cmdFriend(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "info":
		err = cmdInfo(os.Args[2:])
	case "version":
		fmt.Println(banner())
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(banner() + ` - folder-to-folder file transfer over a relay

  ` + appName + ` send     [flags]   set a password, pick files, serve them
  ` + appName + ` receive  [flags]   type the password, pick a drop folder, pull them
  ` + appName + ` scan     [flags]   just show what send would offer
  ` + appName + ` info                 show resolved server, pin cache and paths

common flags
  -server host:port   relay address (default: server= line in ` + appName + `.cfg)
  -chunk MB           force one chunk size for medium and large files
                      (omit it to use the size class: 64 MiB under 10 GB,
                      128 MiB from 10 to 100 GB, 512 MiB over 100 GB)
  -streams N          parallel data connections (default 16)

send
  -dir PATH           folder to scan (default: the folder this exe is in)
  -all                offer everything found without asking
  -flat               list this folder only, do not recurse
  -exclude GLOB,GLOB  skip matching names (case-insensitive)
  -pack MB            fold files this size or smaller into one stream (default 8, 0 off)

receive
  -password PASS      the password your friend set (alias: -code)
  -from FILE          read password, endpoint and pin out of a text file
  -out PATH           drop folder (default: <exe folder>\incoming)
  -show N             picker rows to list (0 for all)
  -all                take every offered file without asking
  -verify             re-hash chunks already on disk before trusting them (default on)
  -fresh              ignore partial progress and start over

The picker lists folders as rows too: picking a folder row takes everything
under it. Sizes are cut by class - 64 MiB chunks under 10 GB, 128 MiB from
10 to 100 GB, 512 MiB over 100 GB - and runs of small files ride together, so
a tree of four thousand tiny files costs a few round-trips instead of four
thousand.
`)
}

// pause holds the console open for an Explorer-launched run.
func pause() {
	fmt.Print("\nPress Enter To Close This Window")
	_, _ = stdin.ReadString('\n')
	fmt.Println()
}

// --- configuration --------------------------------------------------------

// defaultServer is the relay the sender dials when nothing overrides it. The
// build stamps it in with -ldflags "-X main.defaultServer=host:port", so a bare
// exe works with no config file anywhere.
var defaultServer = "127.0.0.1:8443"

// configPath keeps settings out of the tool folder: the exe may sit next to a
// 14 GB game and a stray cfg there is just noise. The temp folder is per-user
// and throwaway, and losing it only falls back to the baked-in default.
func configPath() string {
	return filepath.Join(os.TempDir(), appName, "config")
}

// loadCfg layers the baked default, then a leftover beside-the-exe cfg from
// older builds (migrating it into the temp folder), then the temp config.
func loadCfg() cfg {
	c := cfg{Server: defaultServer, Streams: 16, Pack: 8 << 20}

	for _, legacy := range []string{filepath.Join(exeDir, appName+".cfg"), filepath.Join(exeDir, "SuperTransfer.cfg")} {
		b, err := os.ReadFile(legacy)
		if err != nil {
			continue
		}
		applyCfg(string(b), &c)
		if _, err := os.Stat(configPath()); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err == nil {
				_ = os.WriteFile(configPath(), b, 0o600)
			}
		}
		break
	}

	migrateFile(filepath.Join(os.TempDir(), "SuperTransfer", "config"), configPath())

	if b, err := os.ReadFile(configPath()); err == nil {
		applyCfg(string(b), &c)
	}
	// A build made for one friend carries its relay address and pin; nothing on
	// their disk should be able to redirect it somewhere else.
	if defaultPin != "" && defaultServer != "" {
		c.Server = defaultServer
	}
	return c
}

// migrateFile copies a settings file left by an earlier name of the tool into
// its new home, so a rename never resets somebody's overrides.
func migrateFile(from, to string) {
	if from == to {
		return
	}
	if _, err := os.Stat(to); err == nil {
		return
	}
	b, err := os.ReadFile(from)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err == nil {
		_ = os.WriteFile(to, b, 0o600)
	}
}

// applyCfg reads key=value lines and only overwrites the keys present, so the
// same parser serves both the default layer and an override file.
func applyCfg(body string, c *cfg) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "server":
			if v != "" {
				c.Server = v
			}
		case "chunk":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				c.Chunk = n << 20
			}
		case "streams":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				c.Streams = n
			}
		case "pack":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
				c.Pack = n << 20
			}
		case "password":
			c.Password = v
		case "publicport":
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
				c.PublicPort = n
			}
		}
	}
}

// resolvePassword decides the shared password for a send: the flag wins, then
// the saved one, then whatever is typed, and a generated one if nothing is
// offered. It is remembered so the next send does not ask again.
func resolvePassword(flagVal string) (string, error) {
	if p := strings.TrimSpace(flagVal); p != "" {
		return checkPassword(p)
	}
	def := strings.TrimSpace(appCfg.Password)
	prompt := "Set A Password For This Transfer"
	if def != "" {
		prompt = "Password For This Transfer (Press Enter To Keep The Saved One)"
	}
	got := strings.TrimSpace(askPlain(prompt, def))
	if got == "" && def == "" {
		gen, err := wire.NewToken(16)
		if err != nil {
			return "", err
		}
		fmt.Printf("using a generated password: %s\n", gen)
		return gen, nil
	}
	if got == "" {
		got = def
	}
	p, err := checkPassword(got)
	if err != nil {
		return "", err
	}
	savePassword(p)
	return p, nil
}

func checkPassword(p string) (string, error) {
	if len([]rune(p)) < 8 {
		return "", fmt.Errorf("use a password of at least 8 characters")
	}
	return p, nil
}

// savePassword writes the per-user config back with the password in it.
func savePassword(p string) {
	body := fmt.Sprintf("# Relay this PC sends through.\nserver=%s\nstreams=%d\npack=%d\n",
		appCfg.Server, appCfg.Streams, appCfg.Pack>>20)
	if appCfg.PublicPort > 0 {
		body += fmt.Sprintf("publicport=%d\n", appCfg.PublicPort)
	}
	body += "password=" + p + "\n"
	if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err == nil {
		_ = os.WriteFile(configPath(), []byte(body), 0o600)
	}
	appCfg.Password = p
}

// ensureRelay proves the relay is there before anything else happens. On a hit
// it wipes the console so the transfer starts on a clean screen; on a miss it
// leaves the one instruction that fixes it.
func ensureRelay(addr string) error {
	if relayChecked {
		return nil
	}
	if probeTCP(addr, 700*time.Millisecond) {
		relayChecked = true
		clearScreen()
		fmt.Printf("%s - relay %s connected\n\n", banner(), addr)
		return nil
	}
	if !relayMessageShown {
		relayMissing()
		relayMessageShown = true
	}
	return errReported
}

// showRelayBanner is the startup version: it reports the relay but never stops
// the user, because receiving does not need one on this machine. The "start the
// relay" line only appears where a relay could actually run.
func showRelayBanner(addr string) {
	if relayChecked || !hasLocalRelay() {
		// No relay shipped next to this exe means this is a receiver's PC: its
		// own loopback is irrelevant and claiming "connected" would mislead.
		return
	}
	if probeTCP(addr, 700*time.Millisecond) {
		relayChecked = true
		clearScreen() // the menu prints the logo and the relay line itself
	}
}

// hasLocalRelay reports whether this copy can host, i.e. STRS-Relay.exe sits
// beside it.
func hasLocalRelay() bool {
	_, err := os.Stat(filepath.Join(exeDir, "STRS-Relay.exe"))
	return err == nil
}

// relayChecked stops the second probe (and a second screen clear) once the
// startup check has already answered.
var (
	relayChecked      bool
	relayMessageShown bool
)

// runMenu offers the three things this exe does, after the relay is known good.
func runMenu() error {
	printLogo()
	fmt.Println(banner())
	if relayChecked {
		fmt.Printf("relay %s connected (your PC's side)\n", appCfg.Server)
	} else {
		fmt.Printf("relay %s starts automatically when you send\n", localRelayAddr())
	}
	fmt.Println()
	fmt.Println("  1  Send Files To A Friend   (Set A Password, Share It With Them)")
	fmt.Println("  2  Receive Files            (Receive With Just A Password)")
	fmt.Println()
	choice := strings.TrimSpace(askPlain("Select Choice", "1"))
	fmt.Println()
	switch choice {
	case "1", "send":
		return cmdSend(nil)
	case "2", "receive", "recv", "friend":
		return cmdFriend(nil)
	default:
		return fmt.Errorf("not a menu option: %s", choice)
	}
}

// cmdFriend is the receive-only path: the password is the whole handoff, and
// the relay address is remembered after the first time it is typed in.

// errReported means the failure was already explained on screen; main should
// exit without stamping "error:" on top of a sentence meant for a person.
var errReported = errors.New("reported")

// relayMissing is the one line a person needs when there is no relay to talk to.
func relayMissing() {
	fmt.Println()
	fmt.Println("please start STRS-Relay.exe first!")
	fmt.Println()
}

func probeTCP(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// resolveServer prefers the flag, then SuperTransfer.cfg, then a value that
// came from a pasted block.
func resolveServer(flagVal, pasted string) (string, error) {
	for _, s := range []string{flagVal, pasted, appCfg.Server} {
		if s = strings.TrimSpace(s); s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("no relay address: pass -server host:port or put a server= line in %s", cfgPath)
}

// --- transport ------------------------------------------------------------

// dial connects with TLS and checks the certificate against the pin we expect.
// An expected pin is never downgraded to trust-on-first-use.
func dial(server, expectPin string) (*wire.Conn, string, error) {
	c, err := net.DialTimeout("tcp", server, 15*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("cannot reach relay %s: %w", server, err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "supertransfer-relay",
	})
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return nil, "", fmt.Errorf("TLS handshake with %s: %w", server, err)
	}
	_ = tc.SetDeadline(time.Time{})

	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		_ = tc.Close()
		return nil, "", fmt.Errorf("relay %s presented no certificate", server)
	}
	pin := wire.PinOf(chain[0].Raw)
	if expectPin != "" && !samePin(pin, expectPin) {
		_ = tc.Close()
		return nil, pin, fmt.Errorf("refusing relay %s: pin is %s, expected %s. Either the password block is from an older relay, or something between you and %s is intercepting the connection", server, pin, expectPin, server)
	}
	return wire.Wrap(tc), pin, nil
}

func samePin(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// pinStore caches which pin belongs to which relay host, so the second visit
// catches a swap.
type pinStore map[string]string

func pinStorePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		base = exeDir
	}
	d := filepath.Join(base, appName)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(d, "pins.json"), nil
}

func loadPins() pinStore {
	p := pinStore{}
	path, err := pinStorePath()
	if err != nil {
		return p
	}
	if base, err := os.UserConfigDir(); err == nil {
		migrateFile(filepath.Join(base, "SuperTransfer", "pins.json"), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	_ = json.Unmarshal(b, &p)
	return p
}

// rememberPin caches the pin observed for a relay host. A pin the operator
// handed over deliberately - from a code txt or -pin - replaces the cached
// value, because a re-keyed relay plus a fresh txt is the normal way this
// changes. Anything else is a conflict and gets refused.
func rememberPin(server, pin string, authoritative bool) error {
	path, err := pinStorePath()
	if err != nil {
		return err
	}
	p := loadPins()
	if old, ok := p[server]; ok && !samePin(old, pin) && !authoritative {
		return fmt.Errorf("relay %s changed certificate: was %s, now %s. Pass -pin %s to accept the new one, or delete %s if you moved the relay", server, old, pin, pin, path)
	}
	p[server] = pin
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// expectedPin combines what the caller supplied with the cached value, and
// reports whether the value came from the caller rather than the cache.
func expectedPin(server, supplied string) (string, bool) {
	if s := strings.TrimSpace(supplied); s != "" {
		return s, true
	}
	// A build made for one friend carries the relay's pin, so they never need a
	// block to get pinning right.
	if p := strings.TrimSpace(defaultPin); p != "" {
		return p, true
	}
	return loadPins()[server], false
}

// defaultPin is stamped in at build time with -X main.defaultPin=sha256/... for
// copies handed to somebody else.
var defaultPin = ""

// openConn starts one protocol connection in a role and returns the relay's
// first reply frame plus the certificate pin it presented.
func openConn(server, role, token, name, pin string) (*wire.Conn, wire.Msg, string, error) {
	c, gotPin, err := dial(server, pin)
	if err != nil {
		return nil, wire.Msg{}, gotPin, err
	}
	if err := c.Send(wire.Msg{T: "hello", V: wire.ProtoV, Role: role, Token: token, Name: name}); err != nil {
		_ = c.Close()
		return nil, wire.Msg{}, gotPin, err
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	m, err := c.Recv()
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return nil, wire.Msg{}, gotPin, fmt.Errorf("no reply from relay: %w", err)
	}
	if e := m.AsError(); e != nil {
		_ = c.Close()
		return nil, m, gotPin, fmt.Errorf("%s", e.Text)
	}
	return c, m, gotPin, nil
}

// expectReply fails the connection when the relay's first reply is not the
// frame this role was waiting for.
func expectReply(c *wire.Conn, m wire.Msg, want string) error {
	if m.T != want {
		_ = c.Close()
		return fmt.Errorf("expected %s from the relay, got %q", want, m.T)
	}
	return nil
}

// --- terminal helpers -----------------------------------------------------

func ask(prompt, def string) string {
	outMu.Lock()
	defer outMu.Unlock()
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	return readLine(def)
}

// askPlain prompts without advertising the default in brackets; an empty
// answer still takes it.
func askPlain(prompt, def string) string {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s: ", prompt)
	return readLine(def)
}

func readLine(def string) string {
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return def
	}
	return strings.TrimSpace(line)
}

func confirm(prompt string, def bool) bool {
	suffix := "Y/n"
	if !def {
		suffix = "y/N"
	}
	line := strings.ToLower(ask(fmt.Sprintf("%s (%s)", prompt, suffix), ""))
	switch line {
	case "":
		return def
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return def
	}
}

// status writes an overwriteable progress line; say() prints a permanent one.
// Both stay in plain ASCII because classic cmd.exe does not understand ANSI
// erase sequences.
func status(line string) {
	outMu.Lock()
	defer outMu.Unlock()
	pad := 79 - len(line)
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("\r%s%s", line, strings.Repeat(" ", pad))
}

func clearStatus() {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Print("\r" + strings.Repeat(" ", 79) + "\r")
}

func say(format string, a ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Print("\r" + strings.Repeat(" ", 79) + "\r")
	fmt.Printf(format+"\n", a...)
}

func stdout() io.Writer { return os.Stdout }

func hostLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func parseSizeFlag(mb int64) int64 {
	if mb <= 0 {
		return 0
	}
	return mb << 20
}

// hostOf is the host half of a host:port, or the value itself.
func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// isTerminal tells a double-clicked run from piped or scripted input.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// saveServer remembers the relay a friend's copy should dial.
func saveServer(addr string) {
	body := fmt.Sprintf("# Relay this copy uses.\nserver=%s\nstreams=%d\npack=%d\n", addr, appCfg.Streams, appCfg.Pack>>20)
	if appCfg.PublicPort > 0 {
		body += fmt.Sprintf("publicport=%d\n", appCfg.PublicPort)
	}
	if appCfg.Password != "" {
		body += "password=" + appCfg.Password + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err == nil {
		_ = os.WriteFile(configPath(), []byte(body), 0o600)
	}
	appCfg.Server = addr
}

// cmdFriend is the receive-only path: the password is the whole handoff. A
// pasted block supplies the address too; otherwise it is asked for once and
// remembered, so later runs are password-only.
func cmdFriend(args []string) error {
	fs := flag.NewFlagSet("friend", flag.ExitOnError)
	serverF := fs.String("server", "", "the relay address your friend gave you")
	fs.Parse(args)

	addr := strings.TrimSpace(*serverF)
	explicit := addr != ""
	if !explicit {
		addr = appCfg.Server
	}
	needAddr := !explicit && isLocalHost(hostOf(addr))

	entered := strings.TrimSpace(askPlain("Password (Or Paste The Block They Sent You)", ""))
	if entered == "" {
		return fmt.Errorf("nothing entered")
	}
	pw, pEndpoint, pPin := parsePaste(entered)
	if pw == "" {
		pw = entered
	}
	if pEndpoint != "" {
		addr = pEndpoint
		needAddr = false
	}

	if needAddr {
		addr = strings.TrimSpace(askPlain("Relay Address Your Friend Gave You", ""))
		if addr == "" {
			return fmt.Errorf("the relay address is the line marked endpoint in their block")
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%q is not host:port - it should look like 1.2.3.4:9443", addr)
		}
		saveServer(addr)
		fmt.Printf("saved relay %s for next time\n\n", addr)
	}

	argsIn := []string{"-server", addr, "-password", pw}
	if pPin != "" {
		argsIn = append(argsIn, "-pin", pPin)
	}
	return cmdReceive(argsIn)
}

// logo is the badge in text form: the exe's icon only shows in Explorer, so the
// menu carries a version of the mark too.
const logo = `  ____ _____ ____ ____
 / ___|_   _|  _ \ ___|
 \___ \ | | | |_) / __|
  ___) || | |  _ <\__ \
 |____/ |_| |_| \_\___|`

func printLogo() {
	fmt.Println(logo)
	fmt.Println("             SuperTransferSpeeds")
	fmt.Println()
}
