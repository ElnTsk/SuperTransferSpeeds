package main

import (
	"fmt"
	"strings"
	"time"

	"transfer/internal/relay"
)

// cmdReceiveNearby is "Receive From Nearby": the sender is on the same network
// (or on this very PC), so only the password is needed. Every relay on the
// network that answers is tried with the password until one accepts it.
func cmdReceiveNearby() error {
	entered := strings.TrimSpace(askPlain("Password", ""))
	if entered == "" {
		return fmt.Errorf("nothing entered")
	}
	pw, _, _ := parsePaste(entered)
	if pw == "" {
		pw = entered
	}

	fmt.Println("Looking for a sender on your network...")
	found := relay.Discover(relay.DiscoveryPort, 1500*time.Millisecond)
	if len(found) == 0 {
		fmt.Println()
		fmt.Println("No sender answered. Check that:")
		fmt.Println("  - the sender has STRS open and is waiting (choose 1 there)")
		fmt.Println("  - both PCs are on the same network (same router or Wi-Fi)")
		fmt.Println("  - the sender's firewall allows STRS (Windows asks the first time)")
		fmt.Println("If that is all fine, choose 2 and paste the block your friend sent.")
		fmt.Println()
		return errReported
	}
	fmt.Printf("Found %d sender(s).\n\n", len(found))

	for _, f := range found {
		err := cmdReceive([]string{"-server", f.Addr, "-pin", f.Pin, "-password", pw})
		if err == nil {
			return nil
		}
		// A different sender may be the one using this password; keep looking.
		if strings.Contains(err.Error(), "password not recognised") {
			continue
		}
		return err
	}
	fmt.Println("A sender was found, but it did not accept that password.")
	fmt.Println("Check the password with the person sending, then try again.")
	fmt.Println()
	return errReported
}
