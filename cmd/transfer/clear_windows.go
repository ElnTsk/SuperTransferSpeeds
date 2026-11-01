//go:build windows

package main

import (
	"os"
	"os/exec"
)

// clearScreen asks the console itself to wipe, which works on every Windows
// build; raw ANSI only works when VT processing happens to be enabled.
func clearScreen() {
	c := exec.Command("cmd", "/c", "cls")
	c.Stdout = os.Stdout
	c.Stdin = nil
	_ = c.Run()
}
