//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// freeBytes reports how many bytes can still be written on the volume holding
// path, which is what decides whether a 118 GB drop is even possible.
func freeBytes(path string) (int64, error) {
	// Walk up to an existing directory; GetDiskFreeSpaceEx needs a real path.
	probe := path
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return 0, fmt.Errorf("nothing on the path %s exists yet", path)
		}
		probe = parent
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getEx := kernel32.NewProc("GetDiskFreeSpaceExW")
	var freeAvail, total, totalFree uint64
	p, err := syscall.UTF16PtrFromString(probe)
	if err != nil {
		return 0, err
	}
	r, _, err := getEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&freeAvail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceExW(%s): %w", probe, err)
	}
	intFree := int64(freeAvail)
	if intFree < 0 {
		return 1<<62 - 1, nil
	}
	return intFree, nil
}
