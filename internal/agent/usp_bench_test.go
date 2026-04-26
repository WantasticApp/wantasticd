package agent

import (
	"bytes"
	"io"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

const uspBenchmarkTransferSize = 100 << 20

func BenchmarkUSPRuntimeTunnelTransferUpload100MB(b *testing.B) {
	for _, fixture := range []struct {
		name         string
		compressible bool
	}{
		{name: "structured", compressible: true},
		{name: "random", compressible: false},
	} {
		root := b.TempDir()
		source := writeTransferFixture(b, root, "upload-"+fixture.name+".bin", uspBenchmarkTransferSize, fixture.compressible)

		b.Run(fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(uspBenchmarkTransferSize)

			for i := 0; i < b.N; i++ {
				runtime := newTestUSPRuntime(b)
				target := filepath.Join(root, fixture.name+"-uploaded-"+strconv.Itoa(i)+".bin")
				reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
					ID:     400 + uint64(i),
					Method: wusp.USPAgentMethodUpload,
					Transfer: &wusp.USPTransferRequest{
						Path: "Device.DeviceInfo.VendorConfigFile.1.",
						URI:  "file://" + target,
						Metadata: map[string]string{
							"size": strconv.FormatInt(uspBenchmarkTransferSize, 10),
						},
					},
				})
				if err != nil {
					b.Fatalf("EncodeUSPAgentRequest(upload) returned error: %v", err)
				}

				var controlRespFrame []byte
				replyFn := func(frame []byte) error {
					if controlRespFrame == nil {
						controlRespFrame = append([]byte(nil), frame...)
					}
					return nil
				}
				if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, reqFrame, replyFn); err != nil {
					b.Fatalf("handleFrameFromPeer(upload control) returned error: %v", err)
				}
				resp := decodeControlResponseDatagram(b, controlRespFrame)
				sessionID, err := strconv.ParseUint(resp.Transfer.Metadata[wusp.TransferMetadataSessionID], 10, 64)
				if err != nil {
					b.Fatalf("ParseUint(session_id) returned error: %v", err)
				}

				openFrame, err := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
					SessionID: sessionID,
					RequestID: resp.ID,
					Method:    wusp.USPAgentMethodUpload,
					Phase:     wusp.USPTransferStreamOpen,
					Path:      "Device.DeviceInfo.VendorConfigFile.1.",
				})
				if err != nil {
					b.Fatalf("EncodeUSPTransferStreamFrame(open) returned error: %v", err)
				}
				if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, openFrame, replyFn); err != nil {
					b.Fatalf("handleFrameFromPeer(upload open) returned error: %v", err)
				}

				file, err := os.Open(source)
				if err != nil {
					b.Fatalf("Open(source) returned error: %v", err)
				}

				buf := make([]byte, uspRecommendedChunkSize)
				offset := int64(0)
				sequence := uint32(1)
				for {
					n, readErr := file.Read(buf)
					if n > 0 {
						chunkFrame, err := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
							SessionID: sessionID,
							RequestID: resp.ID,
							Method:    wusp.USPAgentMethodUpload,
							Phase:     wusp.USPTransferStreamChunk,
							Sequence:  sequence,
							Offset:    uint64(offset),
							TotalSize: uspBenchmarkTransferSize,
							Data:      append([]byte(nil), buf[:n]...),
							Final:     readErr == io.EOF,
						})
						if err != nil {
							_ = file.Close()
							b.Fatalf("EncodeUSPTransferStreamFrame(chunk) returned error: %v", err)
						}
						if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, chunkFrame, replyFn); err != nil {
							_ = file.Close()
							b.Fatalf("handleFrameFromPeer(upload chunk %d) returned error: %v", sequence, err)
						}
						offset += int64(n)
						sequence++
					}
					if readErr == io.EOF {
						break
					}
					if readErr != nil {
						_ = file.Close()
						b.Fatalf("Read(source) returned error: %v", readErr)
					}
				}
				_ = file.Close()

				completeFrame, err := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
					SessionID: sessionID,
					RequestID: resp.ID,
					Method:    wusp.USPAgentMethodUpload,
					Phase:     wusp.USPTransferStreamComplete,
					Final:     true,
				})
				if err != nil {
					b.Fatalf("EncodeUSPTransferStreamFrame(complete) returned error: %v", err)
				}
				if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, completeFrame, replyFn); err != nil {
					b.Fatalf("handleFrameFromPeer(upload complete) returned error: %v", err)
				}

				info, err := os.Stat(target)
				if err != nil {
					b.Fatalf("Stat(target) returned error: %v", err)
				}
				if info.Size() != uspBenchmarkTransferSize {
					b.Fatalf("uploaded size=%d want=%d", info.Size(), uspBenchmarkTransferSize)
				}
			}
		})
	}
}

func BenchmarkUSPRuntimeTunnelTransferDownload100MB(b *testing.B) {
	for _, fixture := range []struct {
		name         string
		compressible bool
	}{
		{name: "structured", compressible: true},
		{name: "random", compressible: false},
	} {
		root := b.TempDir()
		source := writeTransferFixture(b, root, "download-"+fixture.name+".bin", uspBenchmarkTransferSize, fixture.compressible)

		b.Run(fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(uspBenchmarkTransferSize)

			for i := 0; i < b.N; i++ {
				runtime := newTestUSPRuntime(b)
				replyCh := make(chan []byte, uspTransferWindowSize*4)
				reqFrame, err := wusp.EncodeUSPAgentRequest(wusp.USPAgentRequest{
					ID:     800 + uint64(i),
					Method: wusp.USPAgentMethodDownload,
					Transfer: &wusp.USPTransferRequest{
						Path: "Device.DeviceInfo.VendorConfigFile.1.",
						URI:  "file://" + source,
					},
				})
				if err != nil {
					b.Fatalf("EncodeUSPAgentRequest(download) returned error: %v", err)
				}

				if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, reqFrame, func(frame []byte) error {
					replyCh <- append([]byte(nil), frame...)
					return nil
				}); err != nil {
					b.Fatalf("handleFrameFromPeer(download control) returned error: %v", err)
				}

				first := <-replyCh
				resp := decodeControlResponseDatagram(b, first)
				sessionID, err := strconv.ParseUint(resp.Transfer.Metadata[wusp.TransferMetadataSessionID], 10, 64)
				if err != nil {
					b.Fatalf("ParseUint(session_id) returned error: %v", err)
				}

				var received int64
				timeout := time.NewTimer(30 * time.Second)
				for {
					select {
					case frame := <-replyCh:
						streamFrame, err := wusp.DecodeUSPTransferStreamFrame(frame)
						if err != nil {
							timeout.Stop()
							b.Fatalf("DecodeUSPTransferStreamFrame returned error: %v", err)
						}
						switch streamFrame.Phase {
						case wusp.USPTransferStreamChunk:
							received += int64(len(streamFrame.Data))
							ackFrame, err := wusp.EncodeUSPTransferStreamFrame(wusp.USPTransferStreamFrame{
								SessionID:   sessionID,
								RequestID:   resp.ID,
								Method:      wusp.USPAgentMethodDownload,
								Phase:       wusp.USPTransferStreamAck,
								AckSequence: streamFrame.Sequence,
							})
							if err != nil {
								timeout.Stop()
								b.Fatalf("EncodeUSPTransferStreamFrame(ack) returned error: %v", err)
							}
							if err := runtime.handleFrameFromPeer(runtime.controllerPublicKeyHex, ackFrame, nil); err != nil {
								timeout.Stop()
								b.Fatalf("handleFrameFromPeer(download ack) returned error: %v", err)
							}
						case wusp.USPTransferStreamComplete:
							timeout.Stop()
							if received != uspBenchmarkTransferSize {
								b.Fatalf("downloaded size=%d want=%d", received, uspBenchmarkTransferSize)
							}
							goto nextIteration
						}
					case <-timeout.C:
						b.Fatal("timeout waiting for streamed download frames")
					}
				}

			nextIteration:
			}
		})
	}
}

func writeTransferFixture(tb testing.TB, dir, name string, size int64, compressible bool) string {
	tb.Helper()

	path := filepath.Join(dir, name)
	file, err := os.Create(path)
	if err != nil {
		tb.Fatalf("Create(%s) returned error: %v", path, err)
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	if compressible {
		copy(buf, bytes.Repeat([]byte("wantastic-usp-wireguard-transfer-block-"), 768))
	} else {
		rng := mathrand.New(mathrand.NewSource(1))
		if _, err := rng.Read(buf); err != nil {
			tb.Fatalf("rng.Read returned error: %v", err)
		}
	}

	written := int64(0)
	for written < size {
		chunk := buf
		if remaining := size - written; remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		if _, err := file.Write(chunk); err != nil {
			tb.Fatalf("Write(%s) returned error: %v", path, err)
		}
		written += int64(len(chunk))
	}
	return path
}
