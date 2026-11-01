//go:build windows

package relay

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func firewallMarker(stateDir string) string { return filepath.Join(stateDir, "firewall.ok") }

func writeFirewallMarker(stateDir, port string) {
	_ = os.MkdirAll(stateDir, 0o700)
	_ = os.WriteFile(firewallMarker(stateDir), []byte(port), 0o600)
}

func addFirewallRule(port string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=STRS Relay", "dir=in", "action=allow", "protocol=TCP",
		"localport="+port, "profile=any").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isElevated() bool {
	return exec.Command("net", "session").Run() == nil
}

// elevateSelf re-runs this exe with the given flags behind a UAC prompt.
func elevateSelf(args string) error {
	verb, _ := syscall.UTF16PtrFromString("runas")
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(args)
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	r, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		return fmt.Errorf("elevation was declined or failed (%d): %v", r, callErr)
	}
	return nil
}

// configureFirewall makes sure Windows lets friends reach the relay. It needs
// administrator rights, so a first interactive run offers a UAC prompt;
// declining leaves the relay working on the LAN only.
func configureFirewall(port, stateDir string, interactive bool, logf func(string, ...any)) {
	marker := firewallMarker(stateDir)
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == port {
		return
	}
	if isElevated() {
		if err := addFirewallRule(port); err != nil {
			logf("firewall: %v", err)
			return
		}
		writeFirewallMarker(stateDir, port)
		logf("firewall: allowed inbound TCP %s", port)
		return
	}
	if !interactive {
		logf("firewall: run once as administrator so TCP %s is reachable from outside", port)
		return
	}
	fmt.Printf("\nWindows blocks incoming connections until a rule exists.\nAllow TCP %s through the firewall now? A UAC prompt will appear. (Y/n) ", port)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "n") {
		logf("firewall: skipped - friends outside your network cannot connect yet")
		return
	}
	if err := elevateSelf(fmt.Sprintf("-install-port %s -state %q", port, stateDir)); err != nil {
		logf("firewall: %v", err)
		return
	}
	for i := 0; i < 60; i++ {
		if _, err := os.Stat(marker); err == nil {
			logf("firewall: allowed inbound TCP %s", port)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("firewall: the elevated helper did not confirm - check Windows Defender Firewall")
}
