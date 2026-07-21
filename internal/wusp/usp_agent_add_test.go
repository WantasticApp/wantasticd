package wusp

import (
	"context"
	"testing"
)

type addRecordingSetter struct {
	objectPath string
}

func (s *addRecordingSetter) Set(context.Context, string, Value) error { return nil }

func (s *addRecordingSetter) Delete(context.Context, ...string) error { return nil }

func (s *addRecordingSetter) Add(_ context.Context, objectPath string, _ *Message) ([]string, error) {
	s.objectPath = objectPath
	return []string{"Device.Firewall.Chain.3.Rule.4."}, nil
}

func TestUSPAgentAddAcceptsConcreteParentTablePath(t *testing.T) {
	agent := NewUSPAgent(USPAgentOptions{})
	initial := NewMessage()
	initial.Set("Device.Firewall.Chain.3.Rule.{i}.Target", String("Accept"))

	paths, err := agent.Add("Device.Firewall.Chain.3.Rule.", initial)
	if err != nil {
		t.Fatalf("Add firewall rule: %v", err)
	}
	if len(paths) != 1 || paths[0] != "Device.Firewall.Chain.3.Rule.1." {
		t.Fatalf("created paths=%v", paths)
	}

	got, err := agent.Get("Device.Firewall.Chain.3.Rule.1.Target")
	if err != nil {
		t.Fatalf("Get added rule target: %v", err)
	}
	value, ok := got.Get("Device.Firewall.Chain.3.Rule.1.Target")
	if !ok || value.AsString() != "Accept" {
		t.Fatalf("target=%q present=%t", value.AsString(), ok)
	}
}

func TestUSPAgentAddForwardsConcreteParentTablePathToBackend(t *testing.T) {
	setter := &addRecordingSetter{}
	agent := NewUSPAgent(USPAgentOptions{Setter: setter})

	paths, err := agent.Add("Device.Firewall.Chain.3.Rule.", NewMessage())
	if err != nil {
		t.Fatalf("Add firewall rule: %v", err)
	}
	if setter.objectPath != "Device.Firewall.Chain.3.Rule." {
		t.Fatalf("backend object path=%q", setter.objectPath)
	}
	if len(paths) != 1 || paths[0] != "Device.Firewall.Chain.3.Rule.4." {
		t.Fatalf("created paths=%v", paths)
	}
}
