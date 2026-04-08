/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestWUSPNoiseTransportRoundTrip(t *testing.T) {
	goroutineLeakCheck(t)

	pair := genTestPair(t, false)

	serverAgent := wusp.NewUSPAgent(wusp.USPAgentOptions{
		FillProfile: wusp.FillProfileRealistic,
		UploadHandler: func(_ context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
			return wusp.USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: int64(len(req.Payload)),
				Metadata: map[string]string{
					"transfer": "upload",
				},
			}, nil
		},
		DownloadHandler: func(_ context.Context, req wusp.USPTransferRequest) (wusp.USPTransferResult, error) {
			return wusp.USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: 16384,
				Metadata: map[string]string{
					"transfer": "download",
				},
			}, nil
		},
	})
	if err := serverAgent.Bootstrap(wusp.FillOptions{
		Profile:   wusp.FillProfileRealistic,
		DeviceID:  "usp:device:test:wusp-noise-server",
		Timestamp: time.Unix(1_700_002_000, 0).UTC(),
	}); err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}

	type responseEnvelope struct {
		resp wusp.USPAgentResponse
		err  error
	}

	serverErrCh := make(chan error, 8)
	clientRespCh := make(chan responseEnvelope, 8)

	pair[1].dev.SetWUSPHandler(func(peer *Peer, data []byte) {
		req, err := wusp.DecodeUSPAgentRequest(data)
		if err != nil {
			select {
			case serverErrCh <- err:
			default:
			}
			return
		}

		resp, err := serverAgent.HandleRequest(context.Background(), req)
		if err != nil {
			select {
			case serverErrCh <- err:
			default:
			}
			return
		}

		frame, err := wusp.EncodeUSPAgentResponse(resp)
		if err != nil {
			select {
			case serverErrCh <- err:
			default:
			}
			return
		}

		peer.SendWUSP(frame)
	})

	pair[0].dev.SetWUSPHandler(func(_ *Peer, data []byte) {
		resp, err := wusp.DecodeUSPAgentResponse(data)
		select {
		case clientRespCh <- responseEnvelope{resp: resp, err: err}:
		default:
		}
	})

	pair.Send(t, Ping, nil)

	clientPeer := mustSinglePeer(t, pair[0].dev)

	sendRequest := func(t *testing.T, req wusp.USPAgentRequest) wusp.USPAgentResponse {
		t.Helper()

		frame, err := wusp.EncodeUSPAgentRequest(req)
		if err != nil {
			t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
		}
		if len(frame) > 1200 {
			t.Fatalf("test request %s encoded to %d bytes, over current WUSP transport budget", uspAgentMethodName(req.Method), len(frame))
		}

		clientPeer.SendWUSP(frame)

		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()

		select {
		case err := <-serverErrCh:
			t.Fatalf("server handler error: %v", err)
		case env := <-clientRespCh:
			if env.err != nil {
				t.Fatalf("DecodeUSPAgentResponse returned error: %v", env.err)
			}
			return env.resp
		case <-timeout.C:
			t.Fatalf("timeout waiting for %s response", uspAgentMethodName(req.Method))
			return wusp.USPAgentResponse{}
		}

		return wusp.USPAgentResponse{}
	}

	getResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     1,
		Method: wusp.USPAgentMethodGet,
		Paths: []string{
			"Device.DeviceInfo.Manufacturer",
			"Device.DeviceInfo.SerialNumber",
		},
	})
	if getResp.Error != "" {
		t.Fatalf("get response error=%q want empty", getResp.Error)
	}
	if getResp.Message == nil || len(getResp.Message.Fields) != 2 {
		t.Fatalf("get response message=%+v want 2 fields", getResp.Message)
	}

	setResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     2,
		Method: wusp.USPAgentMethodSet,
		Message: &wusp.Message{
			Fields: []wusp.Field{
				{Path: "Device.DeviceInfo.FriendlyName", Val: wusp.String("Kitchen Node")},
				{Path: "Device.DeviceInfo.HostName", Val: wusp.String("kitchen-node")},
			},
		},
	})
	if setResp.Error != "" {
		t.Fatalf("set response error=%q want empty", setResp.Error)
	}

	verifySetResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     3,
		Method: wusp.USPAgentMethodGet,
		Paths: []string{
			"Device.DeviceInfo.FriendlyName",
			"Device.DeviceInfo.HostName",
		},
	})
	if verifySetResp.Error != "" {
		t.Fatalf("verify set response error=%q want empty", verifySetResp.Error)
	}
	if verifySetResp.Message.Fields[0].Val.AsString() != "Kitchen Node" {
		t.Fatalf("friendly name=%q want %q", verifySetResp.Message.Fields[0].Val.AsString(), "Kitchen Node")
	}
	if verifySetResp.Message.Fields[1].Val.AsString() != "kitchen-node" {
		t.Fatalf("hostname=%q want %q", verifySetResp.Message.Fields[1].Val.AsString(), "kitchen-node")
	}

	deleteResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     4,
		Method: wusp.USPAgentMethodDelete,
		Paths: []string{
			"Device.DeviceInfo.FriendlyName",
		},
	})
	if deleteResp.Error != "" {
		t.Fatalf("delete response error=%q want empty", deleteResp.Error)
	}

	verifyDeleteResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     5,
		Method: wusp.USPAgentMethodGet,
		Paths: []string{
			"Device.DeviceInfo.FriendlyName",
		},
	})
	if !strings.Contains(verifyDeleteResp.Error, wusp.ErrUSPPathNotFound.Error()) {
		t.Fatalf("verify delete error=%q want contains %q", verifyDeleteResp.Error, wusp.ErrUSPPathNotFound.Error())
	}

	uploadResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     6,
		Method: wusp.USPAgentMethodUpload,
		Transfer: &wusp.USPTransferRequest{
			Path:        "Device.DeviceInfo.SerialNumber",
			URI:         "https://controller.example.net/upload",
			Filename:    "state.bin",
			ContentType: "application/octet-stream",
			Payload:     []byte("hello upload"),
		},
	})
	if uploadResp.Error != "" {
		t.Fatalf("upload response error=%q want empty", uploadResp.Error)
	}
	if uploadResp.Transfer == nil || uploadResp.Transfer.Bytes != int64(len("hello upload")) {
		t.Fatalf("upload response transfer=%+v want bytes=%d", uploadResp.Transfer, len("hello upload"))
	}

	downloadResp := sendRequest(t, wusp.USPAgentRequest{
		ID:     7,
		Method: wusp.USPAgentMethodDownload,
		Transfer: &wusp.USPTransferRequest{
			Path: "Device.DeviceInfo.SoftwareVersion",
			URI:  "https://controller.example.net/download",
		},
	})
	if downloadResp.Error != "" {
		t.Fatalf("download response error=%q want empty", downloadResp.Error)
	}
	if downloadResp.Transfer == nil || downloadResp.Transfer.Bytes != 16384 {
		t.Fatalf("download response transfer=%+v want bytes=16384", downloadResp.Transfer)
	}
}

func mustSinglePeer(tb testing.TB, dev *Device) *Peer {
	tb.Helper()

	dev.peers.RLock()
	defer dev.peers.RUnlock()

	if len(dev.peers.keyMap) != 1 {
		tb.Fatalf("peer count=%d want=1", len(dev.peers.keyMap))
	}
	for _, peer := range dev.peers.keyMap {
		return peer
	}
	tb.Fatal("peer map unexpectedly empty")
	return nil
}

func uspAgentMethodName(method wusp.USPAgentMethod) string {
	switch method {
	case wusp.USPAgentMethodGet:
		return "get"
	case wusp.USPAgentMethodSet:
		return "set"
	case wusp.USPAgentMethodDelete:
		return "delete"
	case wusp.USPAgentMethodUpload:
		return "upload"
	case wusp.USPAgentMethodDownload:
		return "download"
	default:
		return "unknown"
	}
}
