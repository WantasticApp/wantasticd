//go:build linux

package endpoints

import (
	"runtime"
	"syscall"
	"unsafe"
)

func uptimeSeconds() (int64, bool) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, false
	}
	return int64(si.Uptime), true
}

// i2c-dev ioctls (linux/i2c-dev.h).
const (
	i2cRDWR = 0x0707
	i2cMRD  = 0x0001
)

type i2cMsg struct {
	Addr, Flags, Len uint16
	Buf              *byte
}

type i2cRdwr struct {
	Msgs  *i2cMsg
	NMsgs uint32
}

// lm75 reads register 0 (2 bytes) of the sensor at addr on /dev/i2c-1 as
// one combined I2C_RDWR transaction, and converts like libfos
// board_temp_get: byte-swapped s16 * 5 / 128 (tenths of a degree).
func lm75(fd int, addr uint16) (int, bool) {
	reg := []byte{0}
	out := make([]byte, 2)
	msgs := []i2cMsg{
		{Addr: addr, Len: 1, Buf: &reg[0]},
		{Addr: addr, Flags: i2cMRD, Len: 2, Buf: &out[0]},
	}
	data := i2cRdwr{Msgs: &msgs[0], NMsgs: 2}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), i2cRDWR, uintptr(unsafe.Pointer(&data)))
	runtime.KeepAlive(msgs)
	runtime.KeepAlive(reg)
	runtime.KeepAlive(out)
	if errno != 0 {
		return 0, false
	}
	raw := int16(uint16(out[0])<<8 | uint16(out[1]))
	return int(raw) * 5 / 128, true
}

// boardTemps mirrors formGetSysStatus: temp2 = sensor 0x4a (0x49 when
// 0x4a reads 0), temp1 = sensor 0x48. Only with -i2c-sensors.
func boardTemps(env *Env) (t1, t2 int, ok bool) {
	if env == nil || !env.I2C {
		return 0, 0, false
	}
	fd, err := syscall.Open("/dev/i2c-1", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, false
	}
	defer syscall.Close(fd)
	t2, ok2 := lm75(fd, 0x4a)
	if ok2 && t2 == 0 {
		t2, ok2 = lm75(fd, 0x49)
	}
	t1, ok1 := lm75(fd, 0x48)
	return t1, t2, ok1 && ok2
}
