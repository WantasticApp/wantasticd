/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"

	sysprotoControl = 2

	utunOptIfName        = 2
	utunOptEnableChannel = 17
	utunOptEnableNetif   = 20
)

func isOptionalUTUNOptErr(err error) bool {
	return err == nil ||
		err == unix.ENOPROTOOPT ||
		err == unix.ENOTSUP ||
		err == unix.EINVAL
}

// darwinReadBatchSize bounds how many already-queued packets one Read drains
// from the utun socket. utun hands out one packet per read(2), but under load
// several are already waiting; collecting them in one Read lets the device
// stage, encrypt and hand off a whole batch instead of paying a goroutine
// handoff and queue round trip per packet. The drain never waits, so a lone
// packet is delivered exactly as fast as before.
const darwinReadBatchSize = 32

type NativeTun struct {
	name        string
	tunFile     *os.File
	rawConn     syscall.RawConn // non-blocking drain of queued packets; nil disables batching
	drain       utunDrain
	events      chan Event
	errors      chan error
	routeSocket int
	closeOnce   sync.Once
}

func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		statusUp  bool
		statusMTU int
	)

	defer close(tun.events)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR {
				goto retry
			}
			tun.errors <- err
			return
		}

		if n < 28 {
			continue
		}

		if data[3 /* ifm_type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifm_index */])))
		if ifindex != tunIfindex {
			continue
		}

		flags := int(*(*uint32)(unsafe.Pointer(&data[8 /* ifm_flags */])))

		// Up / Down event
		up := (flags & syscall.IFF_UP) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		mtu := int(*(*uint32)(unsafe.Pointer(&data[24 /* ifm_data.ifi_mtu */])))

		// MTU changes
		if mtu != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = mtu
	}
}

func CreateTUN(name string, mtu int) (Device, error) {
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]*")
		}
	}

	fd, err := socketCloexec(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, err
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], []byte(utunControlName))
	err = unix.IoctlCtlInfo(fd, ctlInfo)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("IoctlGetCtlInfo: %w", err)
	}

	enableNetif := 1
	if err := unix.SetsockoptInt(fd, sysprotoControl, utunOptEnableNetif, enableNetif); !isOptionalUTUNOptErr(err) {
		unix.Close(fd)
		return nil, fmt.Errorf("enable utun netif: %w", err)
	} else if err != nil {
		log.Printf("[TUN] utun netif optimization unavailable, falling back to classic utun path: %v", err)
	}
	if err := unix.SetsockoptInt(fd, sysprotoControl, utunOptEnableChannel, 1); !isOptionalUTUNOptErr(err) {
		unix.Close(fd)
		return nil, fmt.Errorf("enable utun channel: %w", err)
	} else if err != nil {
		log.Printf("[TUN] utun channel optimization unavailable, falling back to classic utun path: %v", err)
	}

	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}

	err = unix.Connect(fd, sc)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	tun, err := CreateTUNFromFile(os.NewFile(uintptr(fd), ""), mtu)

	if err == nil && name == "utun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			os.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0o400)
		}
	}

	return tun, err
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 5),
	}
	tun.rawConn = drainConn(file)

	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tun.routeSocket, err = socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	go tun.routineRouteListener(tunIfindex)

	if mtu > 0 {
		err = tun.setMTU(mtu)
		if err != nil {
			tun.Close()
			return nil, err
		}
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	var err error
	tun.operateOnFd(func(fd uintptr) {
		tun.name, err = unix.GetsockoptString(
			int(fd),
			sysprotoControl,
			utunOptIfName,
		)
	})

	if err != nil {
		return "", fmt.Errorf("GetSockoptString: %w", err)
	}

	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// TODO: the BSDs look very similar in Read() and Write(). They should be
	// collapsed, with platform-specific files containing the varying parts of
	// their implementations.
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		buf := bufs[0][offset-4:]
		n, err := tun.tunFile.Read(buf[:])
		if n < 4 {
			return 0, err
		}
		sizes[0] = n - 4
		if err != nil || len(bufs) == 1 || tun.rawConn == nil {
			return 1, err
		}
		return 1 + tun.drain.run(tun.rawConn, bufs[1:], sizes[1:], offset), nil
	}
}

// drainConn returns the raw socket used to drain queued packets, or nil when
// the descriptor is not non-blocking (then Read keeps the classic
// one-packet-per-call behaviour). CreateTUN always sets O_NONBLOCK. Nothing
// may call File().Fd() on a batching NativeTun: Fd() switches the descriptor
// to blocking mode, which would let a drain read wait for a second packet.
func drainConn(file *os.File) syscall.RawConn {
	rc, err := file.SyscallConn()
	if err != nil {
		return nil
	}
	nonblocking := false
	if err := rc.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		nonblocking = err == nil && flags&unix.O_NONBLOCK != 0
	}); err != nil || !nonblocking {
		return nil
	}
	return rc
}

// utunDrain reads packets that are already queued on the utun socket. Its
// callback is bound once so a drain does not allocate a closure per Read.
// Only the single TUN reader goroutine uses it.
type utunDrain struct {
	bufs   [][]byte
	sizes  []int
	offset int
	count  int
	fn     func(fd uintptr) bool
}

// run fills bufs with queued packets without ever waiting: it stops at the
// first EAGAIN (nothing queued), at any other error (the next blocking Read
// reports it) or when bufs is full, and returns how many it read.
func (d *utunDrain) run(rc syscall.RawConn, bufs [][]byte, sizes []int, offset int) int {
	if d.fn == nil {
		d.fn = d.read
	}
	d.bufs, d.sizes, d.offset, d.count = bufs, sizes, offset, 0
	_ = rc.Read(d.fn)
	count := d.count
	d.bufs, d.sizes = nil, nil
	return count
}

func (d *utunDrain) read(fd uintptr) bool {
	for d.count < len(d.bufs) {
		n, err := unix.Read(int(fd), d.bufs[d.count][d.offset-4:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n < 4 {
			break
		}
		d.sizes[d.count] = n - 4
		d.count++
	}
	return true // done: never park waiting for more
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		switch buf[4] >> 4 {
		case 4:
			buf[3] = unix.AF_INET
		case 6:
			buf[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := tun.tunFile.Write(buf); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		if tun.routeSocket != -1 {
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err2 = unix.Close(tun.routeSocket)
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *NativeTun) setMTU(n int) error {
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	var ifr unix.IfreqMTU
	copy(ifr.Name[:], tun.name)
	ifr.MTU = int32(n)
	err = unix.IoctlSetIfreqMTU(fd, &ifr)
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, err)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	ifr, err := unix.IoctlGetIfreqMTU(fd, tun.name)
	if err != nil {
		return 0, fmt.Errorf("failed to get MTU on %s: %w", tun.name, err)
	}

	return int(ifr.MTU), nil
}

func (tun *NativeTun) BatchSize() int {
	if tun.rawConn == nil {
		return 1
	}
	return darwinReadBatchSize
}

func socketCloexec(family, sotype, proto int) (fd int, err error) {
	// See go/src/net/sys_cloexec.go for background.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	fd, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return
}
