package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/internal/wusp"
)

var _ exitNodeController = (*device.Device)(nil)

type fakeExitController struct {
	status  device.ExitNodeStatus
	offer   []bool
	used    []string
	cleared int
	useErr  error
}

func (f *fakeExitController) ExitStatus() device.ExitNodeStatus { return f.status }
func (f *fakeExitController) SetExitOffer(on bool) error {
	f.offer = append(f.offer, on)
	return nil
}
func (f *fakeExitController) UseExitNode(target string, _ time.Duration) (*device.ExitUse, error) {
	f.used = append(f.used, target)
	return &device.ExitUse{IP: target, State: "active"}, f.useErr
}
func (f *fakeExitController) ClearExitNode() error {
	f.cleared++
	return nil
}

type recordingBackend struct{ sets []string }

func (r *recordingBackend) Collect(context.Context, ...string) (*wusp.Message, error) {
	msg := wusp.NewMessage()
	msg.Set("Device.DeviceInfo.HostName", wusp.String("box"))
	return msg, nil
}
func (r *recordingBackend) Set(_ context.Context, path string, _ wusp.Value) error {
	r.sets = append(r.sets, path)
	return nil
}
func (r *recordingBackend) Delete(context.Context, ...string) error { return nil }

func exitValue(msg *wusp.Message, path string) string {
	for _, f := range msg.Fields {
		if f.Path == path {
			return wusp.ValueToString(f.Val)
		}
	}
	return "<missing>"
}

func TestExitNodeBackendReportsStatus(t *testing.T) {
	exit := &fakeExitController{status: device.ExitNodeStatus{
		Supported: true, ClientSupported: true, Offering: true,
		Users:      []device.ExitUser{{IP: "10.0.0.9"}},
		Using:      &device.ExitUse{IP: "10.0.0.2", Hostname: "mini", State: "active", Path: "direct"},
		Candidates: []device.ExitCandidate{{IP: "10.0.0.2", Hostname: "mini", Offers: "yes", Online: true, Path: "direct"}},
	}}
	b := &exitNodeBackend{backend: &recordingBackend{}, exit: exit}
	msg, err := b.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := wusp.WUSPExitNodePrefix
	for path, want := range map[string]string{
		p + "Offer":                    "true",
		p + "ActiveUsers":              "1",
		p + "Use":                      "10.0.0.2",
		p + "UseState":                 "active",
		p + "CandidateNumberOfEntries": "1",
		p + "Candidate.1.Hostname":     "mini",
		p + "Candidate.1.Offers":       "yes",
		"Device.DeviceInfo.HostName":   "box",
	} {
		if got := exitValue(msg, path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}

	exit.status.Using = nil
	// Change notifications are schema-validated; an empty enum would drop them.
	full, _ := b.Collect(context.Background())
	if err := wusp.ValidateMessageFast(full); err != nil {
		t.Fatalf("idle exit-node fields fail validation: %v", err)
	}
	msg, _ = b.Collect(context.Background(), p+"UseState")
	if got := exitValue(msg, p+"UseState"); got != "off" {
		t.Errorf("UseState with no exit node = %q, want off", got)
	}
	if got := exitValue(msg, p+"Offer"); got != "<missing>" {
		t.Errorf("unrequested Offer was returned: %q", got)
	}
}

func TestExitNodeBackendSet(t *testing.T) {
	ctx := context.Background()
	inner := &recordingBackend{}
	exit := &fakeExitController{status: device.ExitNodeStatus{Supported: true, ClientSupported: true}}
	b := &exitNodeBackend{backend: inner, exit: exit}
	p := wusp.WUSPExitNodePrefix

	if err := b.Set(ctx, p+"Offer", wusp.Bool(true)); err != nil || len(exit.offer) != 1 || !exit.offer[0] {
		t.Fatalf("Offer on: err=%v offer=%v", err, exit.offer)
	}
	if err := b.Set(ctx, p+"Use", wusp.String(" 10.0.0.2 ")); err != nil || len(exit.used) != 1 || exit.used[0] != "10.0.0.2" {
		t.Fatalf("Use: err=%v used=%v", err, exit.used)
	}
	for _, bad := range []string{"example.com", "10.0.0.2; reboot", "fd00::1"} {
		if err := b.Set(ctx, p+"Use", wusp.String(bad)); err == nil {
			t.Errorf("Use %q was accepted", bad)
		}
	}
	if len(exit.used) != 1 {
		t.Fatalf("invalid targets reached the device: %v", exit.used)
	}
	if err := b.Set(ctx, p+"Use", wusp.String("")); err != nil || exit.cleared != 1 {
		t.Fatalf("Use empty: err=%v cleared=%d", err, exit.cleared)
	}
	exit.useErr = errors.New("10.0.0.3 has not enabled exit-node")
	if err := b.Set(ctx, p+"Use", wusp.String("10.0.0.3")); err == nil {
		t.Fatal("refused exit node reported success")
	}
	if err := b.Set(ctx, "Device.DeviceInfo.FriendlyName", wusp.String("x")); err != nil || len(inner.sets) != 1 {
		t.Fatalf("other paths must pass through: err=%v sets=%v", err, inner.sets)
	}

	exit.status.Supported, exit.status.ClientSupported = false, false
	if err := b.Set(ctx, p+"Offer", wusp.Bool(true)); err == nil {
		t.Error("Offer accepted on an unsupported device")
	}
	if err := b.Set(ctx, p+"Use", wusp.String("10.0.0.2")); err == nil {
		t.Error("Use accepted on an unsupported device")
	}
}
