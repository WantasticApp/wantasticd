//go:build darwin

package tun

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newSocketpairTun builds a NativeTun over one end of an AF_UNIX datagram
// socketpair, which has the same one-packet-per-read semantics as utun
// (including the 4-byte address-family header). The other end plays the
// kernel.
func newSocketpairTun(tb testing.TB) (*NativeTun, int) {
	tb.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		tb.Fatal(err)
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		tb.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "tun")
	tun := &NativeTun{tunFile: file, errors: make(chan error, 1)}
	tun.rawConn = drainConn(file)
	tb.Cleanup(func() {
		file.Close()
		unix.Close(fds[1])
	})
	return tun, fds[1]
}

func utunFrame(payloadLen int, tag byte) []byte {
	pkt := make([]byte, 4+payloadLen)
	pkt[3] = unix.AF_INET
	pkt[4] = 0x45
	for i := 5; i < len(pkt); i++ {
		pkt[i] = tag
	}
	return pkt
}

func readBufs(n, size int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	return bufs, make([]int, n)
}

func TestDarwinReadDrainsQueuedPackets(t *testing.T) {
	tun, peer := newSocketpairTun(t)
	if got := tun.BatchSize(); got != darwinReadBatchSize {
		t.Fatalf("BatchSize = %d, want %d", got, darwinReadBatchSize)
	}
	const offset = 16
	for i := 0; i < 5; i++ {
		if _, err := unix.Write(peer, utunFrame(100+i, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	bufs, sizes := readBufs(darwinReadBatchSize, 2048)
	n, err := tun.Read(bufs, sizes, offset)
	if err != nil || n != 5 {
		t.Fatalf("Read = %d, %v; want 5 queued packets in one call", n, err)
	}
	for i := 0; i < n; i++ {
		if sizes[i] != 100+i {
			t.Fatalf("packet %d size = %d, want %d", i, sizes[i], 100+i)
		}
		pkt := bufs[i][offset : offset+sizes[i]]
		if pkt[0] != 0x45 || pkt[len(pkt)-1] != byte(i) {
			t.Fatalf("packet %d content/order mismatch", i)
		}
	}
}

func TestDarwinReadDrainRespectsBatchAndDoesNotWait(t *testing.T) {
	tun, peer := newSocketpairTun(t)
	const offset = 4
	for i := 0; i < 10; i++ {
		if _, err := unix.Write(peer, utunFrame(60, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	bufs, sizes := readBufs(4, 2048)
	if n, err := tun.Read(bufs, sizes, offset); err != nil || n != 4 {
		t.Fatalf("Read = %d, %v; want a full batch of 4", n, err)
	}
	if n, err := tun.Read(bufs, sizes, offset); err != nil || n != 4 {
		t.Fatalf("second Read = %d, %v; want 4", n, err)
	}
	// Two left: Read must return them right away, not wait to fill the batch.
	done := make(chan int, 1)
	go func() {
		n, _ := tun.Read(bufs, sizes, offset)
		done <- n
	}()
	select {
	case n := <-done:
		if n != 2 {
			t.Fatalf("tail Read = %d, want 2", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read waited for more packets instead of returning the queued ones")
	}

	// A single packet arriving later is delivered alone, without delay.
	go func() {
		n, _ := tun.Read(bufs, sizes, offset)
		done <- n
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := unix.Write(peer, utunFrame(60, 0xee)); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-done:
		if n != 1 || bufs[0][offset+sizes[0]-1] != 0xee {
			t.Fatalf("lone packet Read = %d", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lone packet was held back")
	}
}

func TestDarwinReadSingleBufferKeepsClassicPath(t *testing.T) {
	tun, peer := newSocketpairTun(t)
	for i := 0; i < 3; i++ {
		if _, err := unix.Write(peer, utunFrame(40, byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	bufs, sizes := readBufs(1, 2048)
	for i := 0; i < 3; i++ {
		n, err := tun.Read(bufs, sizes, 4)
		if err != nil || n != 1 || bufs[0][4+sizes[0]-1] != byte(i) {
			t.Fatalf("Read %d = %d, %v", i, n, err)
		}
	}
}

// BenchmarkDarwinTUNRead measures packets/s pulled off a utun-like socket
// when the reader is behind (packets already queued): batch=1 is the old
// one-packet-per-Read path, batch=32 drains the queue per Read.
func BenchmarkDarwinTUNRead(b *testing.B) {
	for _, batch := range []int{1, darwinReadBatchSize} {
		b.Run(map[int]string{1: "batch=1", darwinReadBatchSize: "batch=32"}[batch], func(b *testing.B) {
			tun, peer := newSocketpairTun(b)
			frame := utunFrame(1400, 1)
			bufs, sizes := readBufs(batch, 2048)
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			b.ResetTimer()
			got := 0
			for got < b.N {
				// Queue up to 64 packets, then read them all back.
				want := min(64, b.N-got)
				for i := 0; i < want; i++ {
					if _, err := unix.Write(peer, frame); err != nil {
						b.Fatal(err)
					}
				}
				for read := 0; read < want; {
					n, err := tun.Read(bufs, sizes, 4)
					if err != nil {
						b.Fatal(err)
					}
					read += n
				}
				got += want
			}
		})
	}
}

func TestDarwinDrainDisabledOnBlockingDescriptor(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "tun")
	defer file.Close()
	defer unix.Close(fds[1])
	if rc := drainConn(file); rc != nil {
		t.Fatal("drain enabled on a blocking descriptor")
	}
	tun := &NativeTun{tunFile: file}
	if got := tun.BatchSize(); got != 1 {
		t.Fatalf("BatchSize = %d, want 1 without a drain", got)
	}
}
