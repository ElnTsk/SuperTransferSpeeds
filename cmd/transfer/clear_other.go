//go:build !windows

package main

import "fmt"

func clearScreen() { fmt.Print("\033[2J\033[H") }
