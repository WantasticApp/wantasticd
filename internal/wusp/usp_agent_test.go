package wusp

import (
	"context"
	"errors"
	"testing"
)

type mockCollector struct {
	msg *Message
	err error
}

func (m mockCollector) Collect(_ context.Context, paths ...string) (*Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.msg == nil {
		return &Message{}, nil
	}
	return subsetMessageByPaths(m.msg, paths...), nil
}

type mockSetter struct {
	setCalls    []string
	deleteCalls []string
	setErr      error
	deleteErr   error
}

func (m *mockSetter) Set(_ context.Context, path string, _ Value) error {
	m.setCalls = append(m.setCalls, path)
	return m.setErr
}

func (m *mockSetter) Delete(_ context.Context, paths ...string) error {
	m.deleteCalls = append(m.deleteCalls, paths...)
	return m.deleteErr
}

func TestUSPAgentBootstrapGetSetDelete(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})

	if err := agent.Bootstrap(FillOptions{Profile: FillProfileRealistic}); err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}

	manufacturer, err := agent.Get("Device.DeviceInfo.Manufacturer")
	if err != nil {
		t.Fatalf("Get(manufacturer) returned error: %v", err)
	}
	if len(manufacturer.Fields) != 1 {
		t.Fatalf("Get(manufacturer) fields=%d want=1", len(manufacturer.Fields))
	}

	if err := agent.Set("Device.DeviceInfo.Manufacturer", String("Wantastic Labs")); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	updated, err := agent.Get("Device.DeviceInfo.Manufacturer")
	if err != nil {
		t.Fatalf("Get(updated manufacturer) returned error: %v", err)
	}
	if got := updated.Fields[0].Val.AsString(); got != "Wantastic Labs" {
		t.Fatalf("manufacturer=%q want %q", got, "Wantastic Labs")
	}

	subtree, err := agent.Get("Device.WireGuard.Peer.{i}.")
	if err != nil {
		t.Fatalf("Get(peer subtree) returned error: %v", err)
	}
	if len(subtree.Fields) == 0 {
		t.Fatal("Get(peer subtree) returned no fields")
	}

	if err := agent.Delete("Device.DeviceInfo.Manufacturer"); err != nil {
		t.Fatalf("Delete(param) returned error: %v", err)
	}
	if _, err := agent.Get("Device.DeviceInfo.Manufacturer"); !errors.Is(err, ErrUSPPathNotFound) {
		t.Fatalf("Get(deleted param) error=%v want ErrUSPPathNotFound", err)
	}

	if err := agent.Delete("Device.WireGuard.Peer.{i}."); err != nil {
		t.Fatalf("Delete(object subtree) returned error: %v", err)
	}
	if _, err := agent.Get("Device.WireGuard.Peer.{i}."); !errors.Is(err, ErrUSPPathNotFound) {
		t.Fatalf("Get(deleted subtree) error=%v want ErrUSPPathNotFound", err)
	}
}

func TestUSPAgentSetRejectsInvalidValue(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})
	if err := agent.Set("Device.DeviceInfo.ManufacturerOUI", String("BAD")); err == nil {
		t.Fatal("Set returned nil error for invalid constrained value")
	}
}

func TestUSPAgentTransferHandlers(t *testing.T) {
	ctx := context.Background()
	uploadCalls := 0
	downloadCalls := 0

	agent := NewUSPAgent(USPAgentOptions{
		UploadHandler: func(ctx context.Context, req USPTransferRequest) (USPTransferResult, error) {
			uploadCalls++
			return USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: int64(len(req.Payload)),
			}, nil
		},
		DownloadHandler: func(ctx context.Context, req USPTransferRequest) (USPTransferResult, error) {
			downloadCalls++
			return USPTransferResult{
				Path:  req.Path,
				URI:   req.URI,
				Bytes: 2048,
			}, nil
		},
	})

	uploadResult, err := agent.Upload(ctx, USPTransferRequest{
		Path:    "Device.DeviceInfo.SerialNumber",
		URI:     "https://controller.example.net/upload",
		Payload: []byte("hello"),
	})
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if uploadResult.Bytes != 5 {
		t.Fatalf("Upload bytes=%d want=5", uploadResult.Bytes)
	}

	downloadResult, err := agent.Download(ctx, USPTransferRequest{
		Path: "Device.DeviceInfo.SoftwareVersion",
		URI:  "https://controller.example.net/download",
	})
	if err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if downloadResult.Bytes != 2048 {
		t.Fatalf("Download bytes=%d want=2048", downloadResult.Bytes)
	}

	if uploadCalls != 1 || downloadCalls != 1 {
		t.Fatalf("uploadCalls=%d downloadCalls=%d want 1/1", uploadCalls, downloadCalls)
	}
}

func TestUSPAgentTransferUnsupported(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})
	_, err := agent.Upload(context.Background(), USPTransferRequest{
		Path: "Device.DeviceInfo.SerialNumber",
		URI:  "https://controller.example.net/upload",
	})
	if !errors.Is(err, ErrUSPTransferUnsupported) {
		t.Fatalf("Upload error=%v want ErrUSPTransferUnsupported", err)
	}
}

func TestUSPAgentCollectorAndSetterDelegation(t *testing.T) {
	setter := &mockSetter{}
	live := &Message{}
	live.SetString("Device.DeviceInfo.HostName", "openwrt-ap")

	agent := NewUSPAgent(USPAgentOptions{
		Collector: mockCollector{msg: live},
		Setter:    setter,
	})

	if err := agent.Set("Device.DeviceInfo.FriendlyName", String("Hallway Node")); err != nil {
		t.Fatalf("Set(friendly name) returned error: %v", err)
	}
	if got := len(setter.setCalls); got != 1 || setter.setCalls[0] != "Device.DeviceInfo.FriendlyName" {
		t.Fatalf("setter set calls=%v want Device.DeviceInfo.FriendlyName", setter.setCalls)
	}

	gotHost, err := agent.Get("Device.DeviceInfo.HostName")
	if err != nil {
		t.Fatalf("Get(hostname) returned error: %v", err)
	}
	if got := gotHost.Fields[0].Val.AsString(); got != "openwrt-ap" {
		t.Fatalf("hostname=%q want %q", got, "openwrt-ap")
	}

	if err := agent.Delete("Device.DeviceInfo.FriendlyName"); err != nil {
		t.Fatalf("Delete(friendly name) returned error: %v", err)
	}
	if got := len(setter.deleteCalls); got != 1 || setter.deleteCalls[0] != "Device.DeviceInfo.FriendlyName" {
		t.Fatalf("setter delete calls=%v want Device.DeviceInfo.FriendlyName", setter.deleteCalls)
	}
}

func TestUSPAgentSetterUnsupportedFallsBackToStore(t *testing.T) {
	setter := &mockSetter{setErr: ErrUSPPathUnsupported}
	agent := NewUSPAgent(USPAgentOptions{Setter: setter})

	if err := agent.Set("Device.DeviceInfo.FriendlyName", String("Office Router")); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	got, err := agent.Get("Device.DeviceInfo.FriendlyName")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.Fields[0].Val.AsString() != "Office Router" {
		t.Fatalf("friendly name=%q want %q", got.Fields[0].Val.AsString(), "Office Router")
	}
}

func TestUSPAgentAddGetInstancesOperateNotifyAndSupport(t *testing.T) {
	operateCalls := 0
	notifyCalls := 0

	agent := NewUSPAgent(USPAgentOptions{
		OperateHandler: func(_ context.Context, commandPath string, input *Message, metadata map[string]string) (*Message, error) {
			operateCalls++
			if commandPath != "Device.WUSP.Request.{i}." {
				t.Fatalf("operate command path=%q", commandPath)
			}
			if metadata["command_key"] != "op-1" {
				t.Fatalf("operate metadata=%v", metadata)
			}
			out := &Message{}
			out.SetString("Device.WUSP.Request.1.Status", "Success")
			if input != nil {
				out.Fields = append(out.Fields, input.Fields...)
			}
			return out, nil
		},
		NotifyHandler: func(_ context.Context, eventPath string, payload *Message, metadata map[string]string) error {
			notifyCalls++
			if eventPath != "Device.WUSP.Subscription.{i}." {
				t.Fatalf("notify event path=%q", eventPath)
			}
			if metadata["subscription_id"] != "sub-1" {
				t.Fatalf("notify metadata=%v", metadata)
			}
			if payload == nil || len(payload.Fields) == 0 {
				t.Fatal("notify payload missing")
			}
			return nil
		},
	})

	instances, err := agent.Add("Device.WireGuard.Peer.{i}.", &Message{
		Fields: []Field{
			{Path: "Device.WireGuard.Peer.{i}.Alias", Val: String("peer-1")},
		},
	})
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if len(instances) != 1 || instances[0] != "Device.WireGuard.Peer.1." {
		t.Fatalf("instances=%v want Device.WireGuard.Peer.1.", instances)
	}

	gotInstances, err := agent.GetInstances("Device.WireGuard.Peer.{i}.")
	if err != nil {
		t.Fatalf("GetInstances returned error: %v", err)
	}
	if len(gotInstances) != 1 || gotInstances[0] != "Device.WireGuard.Peer.1." {
		t.Fatalf("GetInstances=%v want Device.WireGuard.Peer.1.", gotInstances)
	}

	countMsg, err := agent.Get("Device.WireGuard.PeerNumberOfEntries")
	if err != nil {
		t.Fatalf("Get(PeerNumberOfEntries) returned error: %v", err)
	}
	if got := countMsg.Fields[0].Val.AsUint(); got != 1 {
		t.Fatalf("PeerNumberOfEntries=%d want=1", got)
	}

	operateOut, err := agent.Operate(context.Background(), "Device.WUSP.Request.{i}.", &Message{
		Fields: []Field{{Path: "Device.WUSP.Request.1.Command", Val: String("Reboot")}},
	}, map[string]string{"command_key": "op-1"})
	if err != nil {
		t.Fatalf("Operate returned error: %v", err)
	}
	if operateCalls != 1 {
		t.Fatalf("operateCalls=%d want=1", operateCalls)
	}
	if operateOut == nil || len(operateOut.Fields) == 0 {
		t.Fatal("Operate output missing")
	}

	if err := agent.Notify(context.Background(), "Device.WUSP.Subscription.{i}.", &Message{
		Fields: []Field{{Path: "Device.WUSP.Subscription.1.ID", Val: String("sub-1")}},
	}, map[string]string{"subscription_id": "sub-1"}); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if notifyCalls != 1 {
		t.Fatalf("notifyCalls=%d want=1", notifyCalls)
	}

	supportedDM := agent.GetSupportedDM("Device.WireGuard.")
	if supportedDM.RootDataModelVersion != BroadbandRootDataModelVersion {
		t.Fatalf("RootDataModelVersion=%q want=%q", supportedDM.RootDataModelVersion, BroadbandRootDataModelVersion)
	}
	if len(supportedDM.Objects) == 0 || len(supportedDM.Params) == 0 {
		t.Fatalf("supported DM missing objects/params: %+v", supportedDM)
	}

	protocol := agent.GetSupportedProtocol()
	if protocol.Name == "" || protocol.RecommendedChunkSize == 0 {
		t.Fatalf("protocol=%+v want populated protocol info", protocol)
	}
}
