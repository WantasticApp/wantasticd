//go:build cgo

package sdk

/*
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile uint32_t *xpon_window;
static size_t xpon_window_len;
static const char *xpon_mem_path = "/dev/mem";

// xpon_mem_set_path overrides the mem device node before first use.
static void xpon_mem_set_path(const char *path) {
	xpon_mem_path = path;
}

// xpon_mem_init maps the EN75xx register window through the mem device
// (default /dev/mem). Returns 0 on success, errno otherwise. Idempotent;
// callers hold no lock because the Go side serializes through sync.Once.
static int xpon_mem_init(const char *path) {
	if (xpon_window != NULL)
		return 0;
	int fd = open(xpon_mem_path, O_RDWR | O_SYNC);
	if (fd < 0)
		return errno;
	void *p = mmap(NULL, (size_t)0x80000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)0x1FAF0000);
	close(fd);
	if (p == MAP_FAILED)
		return errno;
	xpon_window = (volatile uint32_t *)p;
	xpon_window_len = (size_t)0x80000;
	return 0;
}

// xpon_reg_read32 reads one 32-bit register at an absolute physical
// address inside the mapped window.
static int xpon_reg_read32(uint32_t addr, uint32_t *out) {
	int rc = xpon_mem_init(NULL);
	if (rc != 0)
		return rc;
	uintptr_t off = (uintptr_t)addr - (uintptr_t)0x1FAF0000;
	if (off + 4 > xpon_window_len)
		return EFAULT;
	*out = xpon_window[off / 4];
	return 0;
}

// xpon_reg_write32 writes one 32-bit register.
static int xpon_reg_write32(uint32_t addr, uint32_t val) {
	int rc = xpon_mem_init(NULL);
	if (rc != 0)
		return rc;
	uintptr_t off = (uintptr_t)addr - (uintptr_t)0x1FAF0000;
	if (off + 4 > xpon_window_len)
		return EFAULT;
	xpon_window[off / 4] = val;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

var initOnce sync.Once
var initErr error

// memPath returns the mem device node: WANT_ONU_MEM when set (vendor /dev
// is often read-only squashfs, so the firmware creates /tmp/mem), else the
// standard /dev/mem.
func memPath() string {
	if p := os.Getenv("WANT_ONU_MEM"); p != "" {
		return p
	}
	return "/dev/mem"
}

// ensure runs the mmap init once per process.
func ensure() error {
	initOnce.Do(func() {
		path := memPath()
		C.xpon_mem_set_path(C.CString(path))
		if rc := C.xpon_mem_init(nil); rc != 0 {
			initErr = fmt.Errorf("fiberonu/sdk: %s map failed: %s", path, syscall.Errno(rc))
		}
	})
	return initErr
}

// RegRead reads a 32-bit register at the given absolute physical address.
func RegRead(addr uint32) (uint32, error) {
	if err := ensure(); err != nil {
		return 0, err
	}
	var out C.uint32_t
	if rc := C.xpon_reg_read32(C.uint32_t(addr), &out); rc != 0 {
		return 0, fmt.Errorf("fiberonu/sdk: read 0x%x: %s", addr, syscall.Errno(rc))
	}
	return uint32(out), nil
}

// RegWrite writes a 32-bit register at the given absolute physical address.
func RegWrite(addr, val uint32) error {
	if err := ensure(); err != nil {
		return err
	}
	if rc := C.xpon_reg_write32(C.uint32_t(addr), C.uint32_t(val)); rc != 0 {
		return fmt.Errorf("fiberonu/sdk: write 0x%x: %s", addr, syscall.Errno(rc))
	}
	return nil
}
