//go:build !cgo

package sdk

// RegRead is unavailable without cgo: /dev/mem access is implemented in C.
func RegRead(addr uint32) (uint32, error) { return 0, ErrNotSupported }

// RegWrite is unavailable without cgo.
func RegWrite(addr, val uint32) error { return ErrNotSupported }
