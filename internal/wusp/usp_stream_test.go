package wusp

import (
	"bytes"
	"testing"
)

func TestUSPTransferStreamFrameRoundTrip(t *testing.T) {
	cases := []USPTransferStreamFrame{
		{
			SessionID:   7,
			RequestID:   101,
			Method:      USPAgentMethodUpload,
			Phase:       USPTransferStreamOpen,
			Path:        "Device.DeviceInfo.VendorConfigFile.{i}.",
			Filename:    "backup.cfg",
			ContentType: "application/octet-stream",
			Metadata: map[string]string{
				"sha256": "deadbeef",
			},
		},
		{
			SessionID:   7,
			RequestID:   101,
			Method:      USPAgentMethodUpload,
			Phase:       USPTransferStreamChunk,
			Sequence:    3,
			AckSequence: 2,
			Offset:      2048,
			TotalSize:   8192,
			Data:        bytes.Repeat([]byte("WUSP-CHUNK-"), 512),
			Final:       true,
		},
		{
			SessionID:   9,
			RequestID:   202,
			Method:      USPAgentMethodDownload,
			Phase:       USPTransferStreamAck,
			Sequence:    4,
			AckSequence: 4,
		},
		{
			SessionID: 9,
			RequestID: 202,
			Method:    USPAgentMethodDownload,
			Phase:     USPTransferStreamComplete,
			Final:     true,
			Metadata: map[string]string{
				"status": "complete",
			},
		},
	}

	for _, tc := range cases {
		frame, err := EncodeUSPTransferStreamFrame(tc)
		if err != nil {
			t.Fatalf("EncodeUSPTransferStreamFrame(%v) returned error: %v", tc.Phase, err)
		}
		decoded, err := DecodeUSPTransferStreamFrame(frame)
		if err != nil {
			t.Fatalf("DecodeUSPTransferStreamFrame(%v) returned error: %v", tc.Phase, err)
		}
		if decoded.SessionID != tc.SessionID || decoded.RequestID != tc.RequestID || decoded.Method != tc.Method || decoded.Phase != tc.Phase {
			t.Fatalf("decoded header mismatch: got=%+v want=%+v", decoded, tc)
		}
		if decoded.Sequence != tc.Sequence || decoded.AckSequence != tc.AckSequence || decoded.Offset != tc.Offset || decoded.TotalSize != tc.TotalSize || decoded.Final != tc.Final {
			t.Fatalf("decoded counters mismatch: got=%+v want=%+v", decoded, tc)
		}
		if decoded.Path != tc.Path || decoded.Filename != tc.Filename || decoded.ContentType != tc.ContentType {
			t.Fatalf("decoded strings mismatch: got=%+v want=%+v", decoded, tc)
		}
		if !bytes.Equal(decoded.Data, tc.Data) {
			t.Fatalf("decoded data mismatch: got=%dB want=%dB", len(decoded.Data), len(tc.Data))
		}
	}
}
