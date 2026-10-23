//go:build linux

package modem

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns a master fd and the slave path, like a modem AT port.
func openPTY(t *testing.T) (int, string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no ptmx: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(master) })
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", n)
}

func TestLockedRawATPortTalksAndLocks(t *testing.T) {
	master, slave := openPTY(t)
	atLockDir = t.TempDir()
	t.Cleanup(func() { atLockDir = "/var/lock" })

	f, release, err := openLockedATPort(slave)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(atLockDir, "LCK.."+filepath.Base(slave))
	raw, err := os.ReadFile(lock)
	if err != nil || strings.TrimSpace(string(raw)) != fmt.Sprint(os.Getpid()) || len(raw) != 11 {
		t.Fatalf("lock %q err=%v, want microcom's %%10d\\n PID", raw, err)
	}
	if _, _, err := openLockedATPort(slave); err == nil {
		t.Fatal("second client got the port while it was locked")
	}

	tio, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&(unix.ECHO|unix.ICANON) != 0 || tio.Iflag&unix.ICRNL != 0 || tio.Oflag&unix.OPOST != 0 || tio.Cflag&unix.CSIZE != unix.CS8 {
		t.Fatalf("port not raw: %+v", tio)
	}

	go func() {
		buf := make([]byte, 64)
		n, _ := unix.Read(master, buf)
		if strings.Contains(string(buf[:n]), "ATI") {
			_, _ = unix.Write(master, []byte("ATI\r\r\nQuectel\r\nRM520N-GL\r\n\r\nOK\r\n"))
		}
	}()
	session := &atSession{f: f, reader: bufio.NewReader(f)}
	lines, err := session.sendWithTimeout("ATI", 2*time.Second)
	if err != nil || !strings.Contains(strings.Join(lines, "\n"), "RM520N-GL") {
		t.Fatalf("lines=%q err=%v", lines, err)
	}

	release()
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock not released: %v", err)
	}
}

func TestStaleATLockIsTakenOver(t *testing.T) {
	_, slave := openPTY(t)
	atLockDir = t.TempDir()
	t.Cleanup(func() { atLockDir = "/var/lock" })
	lock := filepath.Join(atLockDir, "LCK.."+filepath.Base(slave))
	if err := os.WriteFile(lock, []byte(fmt.Sprintf("%10d\n", 999999)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, release, err := openLockedATPort(slave)
	if err != nil {
		t.Fatalf("stale lock from a dead PID blocked the port: %v", err)
	}
	release()
}
