package device

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wantastic-agent/internal/device/wireguard-go/conn"
	"wantastic-agent/internal/device/wireguard-go/tun"
	"wantastic-agent/internal/device/wireguard-go/tun/tuntest"
)

// batchTUN models a TUN whose Read returns every packet already queued, up
// to the batch size, without waiting for more: the behaviour of the macOS
// utun drain. batch=1 is the classic one-packet-per-Read TUN.
type batchTUN struct {
	tun.Device
	c      *tuntest.ChannelTUN
	batch  int
	closed chan struct{}
	once   sync.Once
}

func (t *batchTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return t.Device.Close()
}

func (t *batchTUN) BatchSize() int { return t.batch }

func (t *batchTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var msg []byte
	select {
	case msg = <-t.c.Outbound:
	case <-t.closed:
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], msg)
	n := 1
	for n < len(bufs) && n < t.batch {
		select {
		case msg = <-t.c.Outbound:
			sizes[n] = copy(bufs[n][offset:], msg)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func genBatchedTestPair(tb testing.TB, batch int) testPair {
	var pair testPair
	cfg, endpointCfg := genConfigs(tb)
	binds := [2]conn.Bind{conn.NewDefaultBind(), conn.NewDefaultBind()}
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.tun.Outbound = make(chan []byte, 1024)
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		dev := &batchTUN{Device: p.tun.TUN(), c: p.tun, batch: batch, closed: make(chan struct{})}
		p.dev = NewDevice(dev, binds[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Fatal(err)
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatal(err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(pair[i].dev.Close)
	}
	return pair
}

// BenchmarkSendPipelineTUNBatch measures the sender side of the data path
// alone: TUN read -> stage -> encrypt -> sequential sender -> UDP sendmsg,
// with one datagram per syscall as on macOS and Windows. After the handshake
// the receiving device is closed, so the kernel discards the datagrams and the
// receiver cannot cap the rate. batch=1 is the classic one-packet-per-Read
// TUN; batch=32 is the macOS utun drain.
func BenchmarkSendPipelineTUNBatch(b *testing.B) {
	for _, batch := range []int{1, 32} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			pair := genBatchedTestPair(b, batch)
			pair.Send(b, Ping, nil)
			pair.Send(b, Pong, nil)
			pair[0].dev.Close()

			var peer *Peer
			for _, p := range pair[1].dev.peers.keyMap {
				peer = p
			}
			pkt := tuntest.Ping(pair[0].ip, pair[1].ip)
			pkt = append(pkt, make([]byte, 1400-len(pkt))...)
			pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
			wire := uint64(len(pkt) + MessageTransportSize)
			base := peer.txBytes.Load()
			want := base + uint64(b.N)*wire

			out := pair[1].tun.Outbound
			b.SetBytes(int64(len(pkt)))
			b.ResetTimer()
			start := time.Now()
			deadline := start.Add(20 * time.Second)
			sent := 0
			for peer.txBytes.Load() < want && time.Now().Before(deadline) {
				if sent < b.N {
					out <- pkt
					sent++
					continue
				}
				time.Sleep(20 * time.Microsecond)
			}
			elapsed := time.Since(start)
			b.StopTimer()
			got := (peer.txBytes.Load() - base) / wire
			b.ReportMetric(float64(elapsed)/float64(max(got, 1)), "ns/pkt")
			b.ReportMetric(float64(got)*float64(len(pkt))*8/elapsed.Seconds()/1e6, "Mbit/s")
		})
	}
}

// BenchmarkThroughputTUNBatch sends b.N full-size packets from device 1 to
// device 0 over real loopback UDP and reports the sender-side CPU-bound rate.
// It isolates what TUN read batching buys the device pipeline (staging,
// encryption hand-off, sequential sender) on platforms whose UDP bind is one
// datagram per syscall (macOS, Windows).
func BenchmarkThroughputTUNBatch(b *testing.B) {
	for _, batch := range []int{1, 32} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			pair := genBatchedTestPair(b, batch)
			pair.Send(b, Ping, nil)
			pair.Send(b, Pong, nil)

			pkt := tuntest.Ping(pair[0].ip, pair[1].ip)
			pkt = append(pkt, make([]byte, 1400-len(pkt))...)
			// Fix up the IPv4 total length for the padded packet.
			pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))

			var recv atomic.Uint64
			done := make(chan time.Duration, 1)
			go func() {
				var start time.Time
				for {
					select {
					case <-pair[0].tun.Inbound:
					case <-time.After(5 * time.Second):
						done <- 0
						return
					}
					n := recv.Add(1)
					if n == 1 {
						start = time.Now()
					}
					if n == uint64(b.N) {
						done <- time.Since(start)
						return
					}
				}
			}()
			var sent uint64
			out := pair[1].tun.Outbound
			b.ResetTimer()
			deadline := time.Now().Add(20 * time.Second)
			for recv.Load() < uint64(b.N) && time.Now().Before(deadline) {
				select {
				case out <- pkt:
					sent++
				default:
					time.Sleep(50 * time.Microsecond)
				}
			}
			elapsed := <-done
			b.StopTimer()
			if elapsed > 0 {
				b.ReportMetric(float64(elapsed)/float64(b.N), "ns/pkt")
				b.ReportMetric(float64(b.N)*float64(len(pkt))*8/elapsed.Seconds()/1e6, "Mbit/s")
			}
			b.ReportMetric(1-float64(recv.Load())/float64(max(sent, 1)), "loss")
		})
	}
}
