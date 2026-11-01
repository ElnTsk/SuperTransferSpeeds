// Command portmap-check exercises the UPnP package against the real router: it
// discovers the gateway, reads the external address, creates a throwaway
// mapping, reads it back, and removes it again.
package main

import (
	"fmt"
	"os"

	"transfer/internal/upnp"
)

func main() {
	r, err := upnp.Discover()
	if err != nil {
		fmt.Println("discover:", err)
		os.Exit(1)
	}
	fmt.Printf("router     : %s  %s\n", r.Gateway, r.Control)

	if ip, err := r.ExternalIP(); err == nil {
		fmt.Printf("external ip: %s\n", ip)
	} else {
		fmt.Println("external ip:", err)
	}
	if ip, err := r.LocalIP(); err == nil {
		fmt.Printf("local ip   : %s\n", ip)
	} else {
		fmt.Println("local ip   :", err)
	}

	const port = 9447
	if err := r.AddMapping(port, port, "STRS-portcheck"); err != nil {
		fmt.Println("add mapping:", err)
		os.Exit(1)
	}
	fmt.Printf("added      : TCP %d -> this host:%d\n", port, port)

	if c, p, err := r.Mapping(port); err == nil {
		fmt.Printf("readback   : %s:%s\n", c, p)
	} else {
		fmt.Println("readback   :", err)
	}

	if err := r.DeleteMapping(port); err != nil {
		fmt.Println("delete     :", err)
		os.Exit(1)
	}
	fmt.Println("removed    : ok")
}
