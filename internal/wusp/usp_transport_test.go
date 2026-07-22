package wusp

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type uspTransportBenchmarkFixture struct {
	scenarios []uspTransportBenchmarkScenario
}

type uspTransportBenchmarkScenario struct {
	name          string
	request       USPAgentRequest
	response      USPAgentResponse
	requestFrame  []byte
	responseFrame []byte
}

var (
	uspTransportMaxSizeFixtureOnce sync.Once
	uspTransportMaxSizeFixtureData uspTransportBenchmarkFixture
	uspTransportMaxSizeFixtureErr  error
)

func TestUSPAgentTransportRequestRoundTrip(t *testing.T) {
	msg := transportTestMessage()
	model := RuntimeDevice()
	paths := []string{
		"Device.DeviceInfo.Manufacturer",
		"Device.DeviceInfo.SerialNumber",
		"Device.WireGuard.Peer.{i}.",
	}

	cases := []USPAgentRequest{
		{
			ID:     1,
			Method: USPAgentMethodGet,
			Paths:  paths,
		},
		{
			ID:            101,
			Method:        USPAgentMethodGet,
			PathCodes:     selectorsToCodes(model.BatchSelectors("Device.DeviceInfo.Manufacturer", "Device.WireGuard.Peer.{i}.")),
			PathInstances: selectorsToInstances(model.BatchSelectors("Device.DeviceInfo.Manufacturer", "Device.WireGuard.Peer.{i}.")),
			Paths: []string{
				"Device.DeviceInfo.Manufacturer",
				"Device.WireGuard.Peer.{i}.",
			},
		},
		{
			ID:     102,
			Method: USPAgentMethodGet,
			PathCodes: []uint64{
				mustTransportSelector(t, "Device.WireGuard.Peer.1.").Code,
			},
			PathInstances: [][]uint64{
				mustTransportSelector(t, "Device.WireGuard.Peer.1.").Instances,
			},
			Paths: []string{
				"Device.WireGuard.Peer.1.",
			},
		},
		{
			ID:     2,
			Method: USPAgentMethodSet,
			Message: cloneMessageForTransportTests(&Message{
				DeviceID:  msg.DeviceID,
				Timestamp: msg.Timestamp,
				Fields: []Field{
					{Path: "Device.DeviceInfo.FriendlyName", Val: String("Living Room Gateway")},
					{Path: "Device.DeviceInfo.HostName", Val: String("wantastic-openwrt")},
				},
			}),
		},
		{
			ID:         3,
			Method:     USPAgentMethodAdd,
			ObjectPath: "Device.WireGuard.Peer.{i}.",
			Message: cloneMessageForTransportTests(&Message{
				Fields: []Field{
					{Path: "Device.WireGuard.Peer.{i}.Alias", Val: String("peer-added")},
				},
			}),
		},
		{
			ID:         103,
			Method:     USPAgentMethodAdd,
			ObjectCode: mustTransportPathCode(t, "Device.WireGuard.Peer.{i}."),
			ObjectPath: "Device.WireGuard.Peer.{i}.",
			Message: cloneMessageForTransportTests(&Message{
				Fields: []Field{
					{Path: "Device.WireGuard.Peer.{i}.Alias", Val: String("peer-coded")},
				},
			}),
		},
		{
			ID:     4,
			Method: USPAgentMethodDelete,
			Paths: []string{
				"Device.DeviceInfo.FriendlyName",
				"Device.WireGuard.Peer.{i}.",
			},
		},
		{
			ID:         5,
			Method:     USPAgentMethodOperate,
			ObjectPath: "Device.WUSP.Request.{i}.",
			Message: &Message{
				Fields: []Field{
					{Path: "Device.WUSP.Request.1.Command", Val: String("Reboot")},
				},
			},
			Metadata: map[string]string{
				"command_key": "operate-1",
			},
		},
		{
			ID:         6,
			Method:     USPAgentMethodNotify,
			ObjectPath: "Device.WUSP.Subscription.{i}.",
			Message: &Message{
				Fields: []Field{
					{Path: "Device.WUSP.Subscription.1.ID", Val: String("sub-1")},
				},
			},
			Metadata: map[string]string{
				"subscription_id": "sub-1",
			},
		},
		{
			ID:     7,
			Method: USPAgentMethodGetSupportedDM,
			Paths:  []string{"Device.WireGuard."},
		},
		{
			ID:     8,
			Method: USPAgentMethodGetSupportedProtocol,
		},
		{
			ID:     9,
			Method: USPAgentMethodUpload,
			Transfer: &USPTransferRequest{
				Path:        "Device.DeviceInfo.SerialNumber",
				URI:         "https://controller.example.net/upload",
				Filename:    "device-export.bin",
				ContentType: "application/octet-stream",
				Payload:     []byte("hello upload"),
				Metadata: map[string]string{
					"content-sha256": "deadbeef",
					"session":        "upload-1",
				},
			},
		},
		{
			ID:     10,
			Method: USPAgentMethodDownload,
			Transfer: &USPTransferRequest{
				Path:     "Device.DeviceInfo.SoftwareVersion",
				URI:      "https://controller.example.net/download",
				Filename: "firmware.bin",
				Metadata: map[string]string{
					"session": "download-1",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(uspAgentMethodName(tc.Method)+"/request", func(t *testing.T) {
			frame, err := EncodeUSPAgentRequest(tc)
			if err != nil {
				t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
			}
			decoded, err := DecodeUSPAgentRequest(frame)
			if err != nil {
				t.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
			}
			assertUSPAgentRequestEqual(t, tc, decoded)
		})
	}
}

func TestUSPAgentTransportResponseRoundTrip(t *testing.T) {
	msg := transportTestMessage()
	respMessage := cloneMessageForTransportTests(&Message{
		DeviceID:  msg.DeviceID,
		Timestamp: msg.Timestamp,
		Fields: []Field{
			msg.Fields[0],
			msg.Fields[1],
		},
	})

	cases := []USPAgentResponse{
		{
			ID:      11,
			Method:  USPAgentMethodGet,
			Message: respMessage,
		},
		{
			ID:     12,
			Method: USPAgentMethodSet,
		},
		{
			ID:         13,
			Method:     USPAgentMethodAdd,
			ObjectPath: "Device.WireGuard.Peer.{i}.",
			Paths:      []string{"Device.WireGuard.Peer.1."},
		},
		{
			ID:         113,
			Method:     USPAgentMethodAdd,
			ObjectPath: "Device.WireGuard.Peer.{i}.",
			ObjectCode: mustTransportPathCode(t, "Device.WireGuard.Peer.{i}."),
			Paths:      []string{"Device.WireGuard.Peer.1."},
			PathCodes: []uint64{
				mustTransportSelector(t, "Device.WireGuard.Peer.1.").Code,
			},
			PathInstances: [][]uint64{
				mustTransportSelector(t, "Device.WireGuard.Peer.1.").Instances,
			},
		},
		{
			ID:     14,
			Method: USPAgentMethodDelete,
			Error:  "wusp: path not found: Device.DeviceInfo.FriendlyName",
		},
		{
			ID:     15,
			Method: USPAgentMethodGetInstances,
			Paths:  []string{"Device.WireGuard.Peer.1."},
		},
		{
			ID:     115,
			Method: USPAgentMethodGetInstances,
			Paths:  []string{"Device.WireGuard.Peer.1."},
		},
		{
			ID:         16,
			Method:     USPAgentMethodOperate,
			ObjectPath: "Device.WUSP.Request.{i}.",
			Message: &Message{
				Fields: []Field{
					{Path: "Device.WUSP.Request.1.Status", Val: String("Success")},
				},
			},
			Metadata: map[string]string{
				"command_key": "operate-1",
			},
		},
		{
			ID:         17,
			Method:     USPAgentMethodNotify,
			ObjectPath: "Device.WUSP.Subscription.{i}.",
		},
		{
			ID:                 18,
			Method:             USPAgentMethodGetSupportedDM,
			SupportedDataModel: NewUSPAgent(USPAgentOptions{}).GetSupportedDM("Device.WireGuard."),
		},
		{
			ID:       19,
			Method:   USPAgentMethodGetSupportedProtocol,
			Protocol: NewUSPAgent(USPAgentOptions{}).GetSupportedProtocol(),
		},
		{
			ID:     20,
			Method: USPAgentMethodUpload,
			Transfer: &USPTransferResult{
				Path:  "Device.DeviceInfo.SerialNumber",
				URI:   "https://controller.example.net/upload",
				Bytes: 4096,
				Metadata: map[string]string{
					"etag":    "upload-etag",
					"session": "upload-1",
				},
			},
		},
		{
			ID:     21,
			Method: USPAgentMethodDownload,
			Transfer: &USPTransferResult{
				Path:  "Device.DeviceInfo.SoftwareVersion",
				URI:   "https://controller.example.net/download",
				Bytes: 8192,
				Metadata: map[string]string{
					"session": "download-1",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(uspAgentMethodName(tc.Method)+"/response", func(t *testing.T) {
			frame, err := EncodeUSPAgentResponse(tc)
			if err != nil {
				t.Fatalf("EncodeUSPAgentResponse returned error: %v", err)
			}
			decoded, err := DecodeUSPAgentResponse(frame)
			if err != nil {
				t.Fatalf("DecodeUSPAgentResponse returned error: %v", err)
			}
			assertUSPAgentResponseEqual(t, tc, decoded)
		})
	}
}

func TestUSPAgentTransportCompactsSelectorsToCodes(t *testing.T) {
	req := USPAgentRequest{
		ID:     500,
		Method: USPAgentMethodGet,
		Paths: []string{
			"Device.DeviceInfo.Manufacturer",
			"Device.WireGuard.Peer.1.",
		},
	}

	frame, err := EncodeUSPAgentRequest(req)
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
	}
	if frame[3]&(1<<4) == 0 {
		t.Fatalf("request flags=%08b want path-code bit set", frame[3])
	}

	decoded, err := DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
	}
	if len(decoded.PathCodes) != 2 {
		t.Fatalf("decoded path codes=%v", decoded.PathCodes)
	}
	if len(decoded.PathInstances) != 2 {
		t.Fatalf("decoded path instances=%v", decoded.PathInstances)
	}
	if !reflect.DeepEqual(decoded.Paths, req.Paths) {
		t.Fatalf("decoded paths=%v want=%v", decoded.Paths, req.Paths)
	}
	if len(decoded.PathInstances[0]) != 0 {
		t.Fatalf("decoded path instances[0]=%v want empty", decoded.PathInstances[0])
	}
	if !reflect.DeepEqual(decoded.PathInstances[1], []uint64{1}) {
		t.Fatalf("decoded path instances[1]=%v want [1]", decoded.PathInstances[1])
	}

	resp := USPAgentResponse{
		ID:         501,
		Method:     USPAgentMethodAdd,
		ObjectPath: "Device.WireGuard.Peer.{i}.",
		Paths:      []string{"Device.WireGuard.Peer.1."},
	}
	frame, err = EncodeUSPAgentResponse(resp)
	if err != nil {
		t.Fatalf("EncodeUSPAgentResponse returned error: %v", err)
	}
	if frame[3]&(1<<7) == 0 {
		t.Fatalf("response flags=%08b want selector-code bit set", frame[3])
	}

	decodedResp, err := DecodeUSPAgentResponse(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentResponse returned error: %v", err)
	}
	if len(decodedResp.PathCodes) != 1 {
		t.Fatalf("decoded response path codes=%v want one coded selector", decodedResp.PathCodes)
	}
	if decodedResp.ObjectCode == 0 {
		t.Fatal("decoded response object code missing")
	}
	if len(decodedResp.PathInstances) != 1 || !reflect.DeepEqual(decodedResp.PathInstances[0], []uint64{1}) {
		t.Fatalf("decoded response path instances=%v want [[1]]", decodedResp.PathInstances)
	}
	if !reflect.DeepEqual(decodedResp.Paths, resp.Paths) {
		t.Fatalf("decoded response paths=%v want=%v", decodedResp.Paths, resp.Paths)
	}
	if decodedResp.ObjectPath != resp.ObjectPath {
		t.Fatalf("decoded response object path=%q want=%q", decodedResp.ObjectPath, resp.ObjectPath)
	}
}

func TestUSPAgentHandleRequest(t *testing.T) {
	uploadCalls := 0
	downloadCalls := 0

	agent := NewUSPAgent(USPAgentOptions{
		FillProfile: FillProfileRealistic,
		UploadHandler: func(_ context.Context, req USPTransferRequest) (USPTransferResult, error) {
			uploadCalls++
			return USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: int64(len(req.Payload)),
				Metadata: map[string]string{
					"mode": "upload",
				},
			}, nil
		},
		DownloadHandler: func(_ context.Context, req USPTransferRequest) (USPTransferResult, error) {
			downloadCalls++
			return USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: 32768,
				Metadata: map[string]string{
					"mode": "download",
				},
			}, nil
		},
	})

	if err := agent.Bootstrap(FillOptions{
		Profile:   FillProfileRealistic,
		DeviceID:  "usp:device:test:transport-agent",
		Timestamp: time.Unix(1_700_000_999, 0).UTC(),
	}); err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}

	getResp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:     1,
		Method: USPAgentMethodGet,
		Paths: []string{
			"Device.DeviceInfo.Manufacturer",
			"Device.DeviceInfo.SerialNumber",
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(get) returned error: %v", err)
	}
	if getResp.Error != "" {
		t.Fatalf("HandleRequest(get) error=%q want empty", getResp.Error)
	}
	if got := len(getResp.Message.Fields); got != 2 {
		t.Fatalf("HandleRequest(get) fields=%d want=2", got)
	}

	setResp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:     2,
		Method: USPAgentMethodSet,
		Message: &Message{
			Fields: []Field{
				{Path: "Device.DeviceInfo.FriendlyName", Val: String("Hallway Node")},
				{Path: "Device.DeviceInfo.HostName", Val: String("hallway-node")},
			},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(set) returned error: %v", err)
	}
	if setResp.Error != "" {
		t.Fatalf("HandleRequest(set) error=%q want empty", setResp.Error)
	}
	updated, err := agent.Get("Device.DeviceInfo.FriendlyName", "Device.DeviceInfo.HostName")
	if err != nil {
		t.Fatalf("Get(after set) returned error: %v", err)
	}
	if updated.Fields[0].Val.AsString() != "Hallway Node" {
		t.Fatalf("friendly name=%q want %q", updated.Fields[0].Val.AsString(), "Hallway Node")
	}
	if updated.Fields[1].Val.AsString() != "hallway-node" {
		t.Fatalf("hostname=%q want %q", updated.Fields[1].Val.AsString(), "hallway-node")
	}

	deleteResp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:     3,
		Method: USPAgentMethodDelete,
		Paths: []string{
			"Device.DeviceInfo.FriendlyName",
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(delete) returned error: %v", err)
	}
	if deleteResp.Error != "" {
		t.Fatalf("HandleRequest(delete) error=%q want empty", deleteResp.Error)
	}
	if _, err := agent.Get("Device.DeviceInfo.FriendlyName"); !strings.Contains(err.Error(), ErrUSPPathNotFound.Error()) {
		t.Fatalf("Get(after delete) error=%v want path-not-found", err)
	}

	uploadResp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:     4,
		Method: USPAgentMethodUpload,
		Transfer: &USPTransferRequest{
			Path:        "Device.DeviceInfo.SerialNumber",
			URI:         "https://controller.example.net/upload",
			Filename:    "state.bin",
			ContentType: "application/octet-stream",
			Payload:     []byte("upload body"),
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(upload) returned error: %v", err)
	}
	if uploadResp.Transfer == nil || uploadResp.Transfer.Bytes != int64(len("upload body")) {
		t.Fatalf("HandleRequest(upload) transfer=%+v want bytes=%d", uploadResp.Transfer, len("upload body"))
	}

	downloadResp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:     5,
		Method: USPAgentMethodDownload,
		Transfer: &USPTransferRequest{
			Path: "Device.DeviceInfo.SoftwareVersion",
			URI:  "https://controller.example.net/download",
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(download) returned error: %v", err)
	}
	if downloadResp.Transfer == nil || downloadResp.Transfer.Bytes != 32768 {
		t.Fatalf("HandleRequest(download) transfer=%+v want bytes=32768", downloadResp.Transfer)
	}
	if uploadCalls != 1 || downloadCalls != 1 {
		t.Fatalf("uploadCalls=%d downloadCalls=%d want 1/1", uploadCalls, downloadCalls)
	}
}

func TestOperateRequestKeepsObjectAndCommandPathsDistinct(t *testing.T) {
	const commandPath = "Device.WUSP_CellularControl.Interface.1.SendSMS()"
	const objectPath = "Device.WUSP_CellularControl.Interface.1."

	object, command, err := OperationTarget(commandPath)
	if err != nil {
		t.Fatalf("OperationTarget returned error: %v", err)
	}
	if object != objectPath || command != commandPath {
		t.Fatalf("OperationTarget=%q/%q want %q/%q", object, command, objectPath, commandPath)
	}

	frame, err := EncodeUSPAgentRequest(USPAgentRequest{
		ID:         91,
		Method:     USPAgentMethodOperate,
		ObjectPath: object,
		Metadata:   WithOperationCommandPath(nil, command),
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
	}
	decoded, err := DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
	}
	if decoded.ObjectPath != objectPath {
		t.Fatalf("decoded object path=%q want %q", decoded.ObjectPath, objectPath)
	}
	gotCommand, err := OperationCommandPath(decoded.ObjectPath, decoded.Metadata)
	if err != nil {
		t.Fatalf("OperationCommandPath returned error: %v", err)
	}
	if gotCommand != commandPath {
		t.Fatalf("decoded command=%q want %q", gotCommand, commandPath)
	}

	_, err = EncodeUSPAgentRequest(USPAgentRequest{
		ID:         92,
		Method:     USPAgentMethodOperate,
		ObjectPath: objectPath,
		Metadata: WithOperationCommandPath(nil,
			"Device.WUSP_CellularControl.Interface.2.SendSMS()"),
	})
	if err == nil {
		t.Fatal("expected mismatched command/object request to be rejected")
	}
}

func TestOperateRequestCarriesCellularSMSInputsByStringPath(t *testing.T) {
	const commandPath = "Device.WUSP_CellularControl.Interface.1.SendSMS()"
	const objectPath = "Device.WUSP_CellularControl.Interface.1."

	input := NewMessage()
	input.Set(objectPath+"SMS.PhoneNumber", String("+212709251456"))
	input.Set(objectPath+"SMS.Message", String("hello"))

	frame, err := EncodeUSPAgentRequest(USPAgentRequest{
		ID:         94,
		Method:     USPAgentMethodOperate,
		ObjectPath: objectPath,
		Message:    input,
		Metadata:   WithOperationCommandPath(nil, commandPath),
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
	}
	decoded, err := DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
	}
	for path, want := range map[string]string{
		objectPath + "SMS.PhoneNumber": "+212709251456",
		objectPath + "SMS.Message":     "hello",
	} {
		got, ok := decoded.Message.Get(path)
		if !ok {
			t.Fatalf("decoded message missing %s", path)
		}
		if ValueToString(got) != want {
			t.Fatalf("decoded %s=%q want %q", path, ValueToString(got), want)
		}
	}
}

func TestOperateRequestAllowsForwardCompatibleInputFields(t *testing.T) {
	const commandPath = "Device.WUSP_CellularControl.Interface.1.SendSMS()"
	const objectPath = "Device.WUSP_CellularControl.Interface.1."
	const futurePath = objectPath + "SMS.FutureFlag"

	input := NewMessage()
	input.Set(futurePath, String("enabled"))

	frame, err := EncodeUSPAgentRequest(USPAgentRequest{
		ID:         95,
		Method:     USPAgentMethodOperate,
		ObjectPath: objectPath,
		Message:    input,
		Metadata:   WithOperationCommandPath(nil, commandPath),
	})
	if err != nil {
		t.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
	}
	decoded, err := DecodeUSPAgentRequest(frame)
	if err != nil {
		t.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
	}
	got, ok := decoded.Message.Get(futurePath)
	if !ok {
		t.Fatalf("decoded message missing forward-compatible input %s", futurePath)
	}
	if ValueToString(got) != "enabled" {
		t.Fatalf("decoded forward-compatible input=%q want enabled", ValueToString(got))
	}
}

func TestUSPAgentHandleOperateUsesMetadataCommandPath(t *testing.T) {
	const commandPath = "Device.WUSP_CellularControl.Interface.1.RefreshGNSS()"
	const objectPath = "Device.WUSP_CellularControl.Interface.1."

	var invoked string
	agent := NewUSPAgent(USPAgentOptions{
		OperateHandler: func(_ context.Context, path string, _ *Message, _ map[string]string) (*Message, error) {
			invoked = path
			return NewMessage(), nil
		},
	})

	resp, err := agent.HandleRequest(context.Background(), USPAgentRequest{
		ID:         93,
		Method:     USPAgentMethodOperate,
		ObjectPath: objectPath,
		Metadata:   WithOperationCommandPath(nil, commandPath),
	})
	if err != nil {
		t.Fatalf("HandleRequest returned error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("HandleRequest response error=%q", resp.Error)
	}
	if invoked != commandPath {
		t.Fatalf("handler command=%q want %q", invoked, commandPath)
	}
}

func BenchmarkUSPAgentTransportEncodeMaxSize(b *testing.B) {
	fixture := mustUSPTransportMaxSizeFixture(b)

	for _, scenario := range fixture.scenarios {
		b.Run("request/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				frame, err := EncodeUSPAgentRequest(scenario.request)
				if err != nil {
					b.Fatalf("EncodeUSPAgentRequest returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("EncodeUSPAgentRequest returned empty frame")
				}
			}
		})

		b.Run("response/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				frame, err := EncodeUSPAgentResponse(scenario.response)
				if err != nil {
					b.Fatalf("EncodeUSPAgentResponse returned error: %v", err)
				}
				if len(frame) == 0 {
					b.Fatal("EncodeUSPAgentResponse returned empty frame")
				}
			}
		})
	}
}

func BenchmarkUSPAgentTransportDecodeMaxSize(b *testing.B) {
	fixture := mustUSPTransportMaxSizeFixture(b)

	for _, scenario := range fixture.scenarios {
		b.Run("request/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(scenario.requestFrame)))
			for i := 0; i < b.N; i++ {
				req, err := DecodeUSPAgentRequest(scenario.requestFrame)
				if err != nil {
					b.Fatalf("DecodeUSPAgentRequest returned error: %v", err)
				}
				if req.Method != scenario.request.Method {
					b.Fatalf("method=%v want %v", req.Method, scenario.request.Method)
				}
			}
		})

		b.Run("response/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(scenario.responseFrame)))
			for i := 0; i < b.N; i++ {
				resp, err := DecodeUSPAgentResponse(scenario.responseFrame)
				if err != nil {
					b.Fatalf("DecodeUSPAgentResponse returned error: %v", err)
				}
				if resp.Method != scenario.response.Method {
					b.Fatalf("method=%v want %v", resp.Method, scenario.response.Method)
				}
			}
		})
	}
}

func BenchmarkUSPAgentHandleRequestMaxSize(b *testing.B) {
	fixture := mustUSPTransportMaxSizeFixture(b)

	for _, scenario := range fixture.scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			agent := newBenchmarkTransportAgent(b)
			b.ReportAllocs()
			if len(scenario.requestFrame) > 0 {
				b.SetBytes(int64(len(scenario.requestFrame)))
			}
			for i := 0; i < b.N; i++ {
				if scenario.request.Method == USPAgentMethodDelete {
					agent = newBenchmarkTransportAgent(b)
				}
				resp, err := agent.HandleRequest(context.Background(), scenario.request)
				if err != nil {
					b.Fatalf("HandleRequest returned error: %v", err)
				}
				if resp.Method != scenario.request.Method {
					b.Fatalf("response method=%v want %v", resp.Method, scenario.request.Method)
				}
			}
		})
	}
}

func mustUSPTransportMaxSizeFixture(tb testing.TB) uspTransportBenchmarkFixture {
	tb.Helper()
	uspTransportMaxSizeFixtureOnce.Do(func() {
		uspTransportMaxSizeFixtureData, uspTransportMaxSizeFixtureErr = buildUSPTransportMaxSizeFixture()
	})
	if uspTransportMaxSizeFixtureErr != nil {
		tb.Fatalf("buildUSPTransportMaxSizeFixture returned error: %v", uspTransportMaxSizeFixtureErr)
	}
	return uspTransportMaxSizeFixtureData
}

func buildUSPTransportMaxSizeFixture() (uspTransportBenchmarkFixture, error) {
	base, err := buildMethodsFixture(
		FillProfileRealistic,
		"usp:device:bench:transport:max-size",
		time.Unix(1_700_001_111, 123456789).UTC(),
	)
	if err != nil {
		return uspTransportBenchmarkFixture{}, err
	}

	allPaths := make([]string, 0, len(base.msg.Fields))
	for _, field := range base.msg.Fields {
		allPaths = append(allPaths, field.Path)
	}

	uploadPayload := append([]byte(nil), base.raw...)
	sharedMetadata := map[string]string{
		"device_id": base.msg.DeviceID,
		"profile":   string(FillProfileRealistic),
	}

	scenarios := []uspTransportBenchmarkScenario{
		{
			name: "get",
			request: USPAgentRequest{
				ID:     1,
				Method: USPAgentMethodGet,
				Paths:  append([]string(nil), allPaths...),
			},
			response: USPAgentResponse{
				ID:      1,
				Method:  USPAgentMethodGet,
				Message: cloneMessageForTransportTests(base.msg),
			},
		},
		{
			name: "set",
			request: USPAgentRequest{
				ID:      2,
				Method:  USPAgentMethodSet,
				Message: cloneMessageForTransportTests(base.msg),
			},
			response: USPAgentResponse{
				ID:     2,
				Method: USPAgentMethodSet,
			},
		},
		{
			name: "delete",
			request: USPAgentRequest{
				ID:     3,
				Method: USPAgentMethodDelete,
				Paths:  append([]string(nil), allPaths...),
			},
			response: USPAgentResponse{
				ID:     3,
				Method: USPAgentMethodDelete,
			},
		},
		{
			name: "upload",
			request: USPAgentRequest{
				ID:     4,
				Method: USPAgentMethodUpload,
				Transfer: &USPTransferRequest{
					Path:        "Device.DeviceInfo.SerialNumber",
					URI:         "https://controller.example.net/upload/usp-agent",
					Filename:    "max-size.bin",
					ContentType: "application/octet-stream",
					Payload:     uploadPayload,
					Metadata:    cloneStringMapForTransportTests(sharedMetadata),
				},
			},
			response: USPAgentResponse{
				ID:     4,
				Method: USPAgentMethodUpload,
				Transfer: &USPTransferResult{
					Path:     "Device.DeviceInfo.SerialNumber",
					URI:      "https://controller.example.net/upload/usp-agent",
					Bytes:    int64(len(uploadPayload)),
					Metadata: cloneStringMapForTransportTests(sharedMetadata),
				},
			},
		},
		{
			name: "download",
			request: USPAgentRequest{
				ID:     5,
				Method: USPAgentMethodDownload,
				Transfer: &USPTransferRequest{
					Path:     "Device.DeviceInfo.SoftwareVersion",
					URI:      "https://controller.example.net/download/usp-agent",
					Filename: "firmware.img",
					Metadata: cloneStringMapForTransportTests(sharedMetadata),
				},
			},
			response: USPAgentResponse{
				ID:     5,
				Method: USPAgentMethodDownload,
				Transfer: &USPTransferResult{
					Path:     "Device.DeviceInfo.SoftwareVersion",
					URI:      "https://controller.example.net/download/usp-agent",
					Bytes:    int64(len(base.raw)),
					Metadata: cloneStringMapForTransportTests(sharedMetadata),
				},
			},
		},
	}

	for i := range scenarios {
		requestFrame, err := EncodeUSPAgentRequest(scenarios[i].request)
		if err != nil {
			return uspTransportBenchmarkFixture{}, err
		}
		responseFrame, err := EncodeUSPAgentResponse(scenarios[i].response)
		if err != nil {
			return uspTransportBenchmarkFixture{}, err
		}
		scenarios[i].requestFrame = requestFrame
		scenarios[i].responseFrame = responseFrame
	}

	return uspTransportBenchmarkFixture{scenarios: scenarios}, nil
}

func newBenchmarkTransportAgent(tb testing.TB) *USPAgent {
	tb.Helper()
	agent := NewUSPAgent(USPAgentOptions{
		FillProfile: FillProfileRealistic,
		UploadHandler: func(_ context.Context, req USPTransferRequest) (USPTransferResult, error) {
			return USPTransferResult{
				Path:     req.Path,
				URI:      req.URI,
				Bytes:    int64(len(req.Payload)),
				Metadata: cloneStringMapForTransportTests(req.Metadata),
			}, nil
		},
		DownloadHandler: func(_ context.Context, req USPTransferRequest) (USPTransferResult, error) {
			return USPTransferResult{
				Path:     req.Path,
				URI:      req.URI,
				Bytes:    65536,
				Metadata: cloneStringMapForTransportTests(req.Metadata),
			}, nil
		},
	})
	if err := agent.Bootstrap(FillOptions{
		Profile:   FillProfileRealistic,
		DeviceID:  "usp:device:bench:transport:agent",
		Timestamp: time.Unix(1_700_001_222, 0).UTC(),
	}); err != nil {
		tb.Fatalf("Bootstrap returned error: %v", err)
	}
	return agent
}

func transportTestMessage() *Message {
	return cloneMessageForTransportTests(&Message{
		DeviceID:  "usp:device:test:transport",
		Timestamp: time.Unix(1_700_000_555, 123456789).UTC(),
		Fields: []Field{
			{Path: "Device.DeviceInfo.Manufacturer", Val: String("Wantastic Labs")},
			{Path: "Device.DeviceInfo.SerialNumber", Val: String("WG-0001")},
		},
	})
}

func assertUSPAgentRequestEqual(t *testing.T, want, got USPAgentRequest) {
	t.Helper()

	if want.ID != got.ID {
		t.Fatalf("request id=%d want=%d", got.ID, want.ID)
	}
	if want.Method != got.Method {
		t.Fatalf("request method=%v want=%v", got.Method, want.Method)
	}
	if len(want.Paths) != len(got.Paths) {
		t.Fatalf("request paths len=%d want=%d", len(got.Paths), len(want.Paths))
	}
	for i := range want.Paths {
		if want.Paths[i] != got.Paths[i] {
			t.Fatalf("request paths[%d]=%q want=%q", i, got.Paths[i], want.Paths[i])
		}
	}
	if want.ObjectPath != got.ObjectPath {
		t.Fatalf("request objectPath=%q want=%q", got.ObjectPath, want.ObjectPath)
	}
	if len(want.PathCodes) > 0 && !reflect.DeepEqual(want.PathCodes, got.PathCodes) {
		t.Fatalf("request pathCodes mismatch: got=%v want=%v", got.PathCodes, want.PathCodes)
	}
	if len(want.PathInstances) > 0 && !equalSelectorInstances(want.PathInstances, got.PathInstances) {
		t.Fatalf("request pathInstances mismatch: got=%v want=%v", got.PathInstances, want.PathInstances)
	}
	if want.ObjectCode != 0 && want.ObjectCode != got.ObjectCode {
		t.Fatalf("request objectCode=%d want=%d", got.ObjectCode, want.ObjectCode)
	}
	if len(want.ObjectInstances) > 0 && !reflect.DeepEqual(normalizeSelectorInstanceList(want.ObjectInstances), normalizeSelectorInstanceList(got.ObjectInstances)) {
		t.Fatalf("request objectInstances mismatch: got=%v want=%v", got.ObjectInstances, want.ObjectInstances)
	}
	if !reflect.DeepEqual(want.Metadata, got.Metadata) {
		t.Fatalf("request metadata mismatch: got=%v want=%v", got.Metadata, want.Metadata)
	}
	assertOptionalMessageEqual(t, want.Message, got.Message)
	assertTransferRequestEqual(t, want.Transfer, got.Transfer)
}

func assertUSPAgentResponseEqual(t *testing.T, want, got USPAgentResponse) {
	t.Helper()

	if want.ID != got.ID {
		t.Fatalf("response id=%d want=%d", got.ID, want.ID)
	}
	if want.Method != got.Method {
		t.Fatalf("response method=%v want=%v", got.Method, want.Method)
	}
	if want.Error != got.Error {
		t.Fatalf("response error=%q want=%q", got.Error, want.Error)
	}
	if !reflect.DeepEqual(want.Paths, got.Paths) {
		t.Fatalf("response paths mismatch: got=%v want=%v", got.Paths, want.Paths)
	}
	if want.ObjectPath != got.ObjectPath {
		t.Fatalf("response objectPath=%q want=%q", got.ObjectPath, want.ObjectPath)
	}
	if len(want.PathCodes) > 0 && !reflect.DeepEqual(want.PathCodes, got.PathCodes) {
		t.Fatalf("response pathCodes mismatch: got=%v want=%v", got.PathCodes, want.PathCodes)
	}
	if len(want.PathInstances) > 0 && !equalSelectorInstances(want.PathInstances, got.PathInstances) {
		t.Fatalf("response pathInstances mismatch: got=%v want=%v", got.PathInstances, want.PathInstances)
	}
	if want.ObjectCode != 0 && want.ObjectCode != got.ObjectCode {
		t.Fatalf("response objectCode=%d want=%d", got.ObjectCode, want.ObjectCode)
	}
	if len(want.ObjectInstances) > 0 && !reflect.DeepEqual(normalizeSelectorInstanceList(want.ObjectInstances), normalizeSelectorInstanceList(got.ObjectInstances)) {
		t.Fatalf("response objectInstances mismatch: got=%v want=%v", got.ObjectInstances, want.ObjectInstances)
	}
	if !reflect.DeepEqual(want.Metadata, got.Metadata) {
		t.Fatalf("response metadata mismatch: got=%v want=%v", got.Metadata, want.Metadata)
	}
	if !reflect.DeepEqual(want.SupportedDataModel, got.SupportedDataModel) {
		t.Fatalf("response supported data model mismatch")
	}
	if !reflect.DeepEqual(want.Protocol, got.Protocol) {
		t.Fatalf("response protocol mismatch: got=%+v want=%+v", got.Protocol, want.Protocol)
	}
	assertOptionalMessageEqual(t, want.Message, got.Message)
	assertTransferResultEqual(t, want.Transfer, got.Transfer)
}

func assertOptionalMessageEqual(t *testing.T, want, got *Message) {
	t.Helper()

	switch {
	case want == nil && got == nil:
		return
	case want == nil || got == nil:
		t.Fatalf("message mismatch: got=%v want=%v", got, want)
	default:
		assertMessageEqual(t, want, got)
	}
}

func assertTransferRequestEqual(t *testing.T, want, got *USPTransferRequest) {
	t.Helper()

	switch {
	case want == nil && got == nil:
		return
	case want == nil || got == nil:
		t.Fatalf("transfer request mismatch: got=%v want=%v", got, want)
	}

	if want.Path != got.Path || want.URI != got.URI || want.Filename != got.Filename || want.ContentType != got.ContentType {
		t.Fatalf("transfer request scalar mismatch: got=%+v want=%+v", got, want)
	}
	if !bytes.Equal(want.Payload, got.Payload) {
		t.Fatalf("transfer request payload mismatch: got=%dB want=%dB", len(got.Payload), len(want.Payload))
	}
	if !reflect.DeepEqual(want.Metadata, got.Metadata) {
		t.Fatalf("transfer request metadata mismatch: got=%v want=%v", got.Metadata, want.Metadata)
	}
}

func assertTransferResultEqual(t *testing.T, want, got *USPTransferResult) {
	t.Helper()

	switch {
	case want == nil && got == nil:
		return
	case want == nil || got == nil:
		t.Fatalf("transfer result mismatch: got=%v want=%v", got, want)
	}

	if want.Path != got.Path || want.URI != got.URI || want.Bytes != got.Bytes {
		t.Fatalf("transfer result scalar mismatch: got=%+v want=%+v", got, want)
	}
	if !reflect.DeepEqual(want.Metadata, got.Metadata) {
		t.Fatalf("transfer result metadata mismatch: got=%v want=%v", got.Metadata, want.Metadata)
	}
}

func mustTransportPathCode(t *testing.T, path string) uint64 {
	t.Helper()
	code, ok := RuntimeDevice().PathCode(path)
	if !ok || code == 0 {
		t.Fatalf("path code missing for %s", path)
	}
	return code
}

func mustTransportSelector(t *testing.T, path string) PathSelector {
	t.Helper()
	selector, ok := RuntimeDevice().SelectorForPath(path)
	if !ok || selector.Code == 0 {
		t.Fatalf("path selector missing for %s", path)
	}
	return selector
}

func selectorsToCodes(selectors []PathSelector) []uint64 {
	out := make([]uint64, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, selector.Code)
	}
	return out
}

func selectorsToInstances(selectors []PathSelector) [][]uint64 {
	out := make([][]uint64, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, append([]uint64(nil), selector.Instances...))
	}
	return out
}

func equalSelectorInstances(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(normalizeSelectorInstanceList(a[i]), normalizeSelectorInstanceList(b[i])) {
			return false
		}
	}
	return true
}

func normalizeSelectorInstanceList(in []uint64) []uint64 {
	if len(in) == 0 {
		return []uint64{}
	}
	return in
}

func cloneMessageForTransportTests(msg *Message) *Message {
	if msg == nil {
		return nil
	}
	cloned := &Message{
		DeviceID:  msg.DeviceID,
		Timestamp: msg.Timestamp,
		Fields:    make([]Field, 0, len(msg.Fields)),
	}
	for _, field := range msg.Fields {
		cloned.Fields = append(cloned.Fields, cloneField(field))
	}
	return cloned
}

func cloneStringMapForTransportTests(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func uspAgentMethodName(method USPAgentMethod) string {
	switch method {
	case USPAgentMethodGet:
		return "get"
	case USPAgentMethodSet:
		return "set"
	case USPAgentMethodAdd:
		return "add"
	case USPAgentMethodDelete:
		return "delete"
	case USPAgentMethodGetInstances:
		return "get-instances"
	case USPAgentMethodOperate:
		return "operate"
	case USPAgentMethodNotify:
		return "notify"
	case USPAgentMethodGetSupportedDM:
		return "get-supported-dm"
	case USPAgentMethodGetSupportedProtocol:
		return "get-supported-protocol"
	case USPAgentMethodUpload:
		return "upload"
	case USPAgentMethodDownload:
		return "download"
	default:
		return "unknown"
	}
}
