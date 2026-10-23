package platforms

import (
	"context"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func ghostTopology() *meshNode {
	live := &meshNode{mac: "aa:00:00:00:00:03", name: "G1TK7EY000096", ip: "192.168.200.15"}
	ghostChild := &meshNode{mac: "e0:5d:54:4b:e7:0e", ip: "0.0.0.0"}
	ghost := &meshNode{mac: "e0:5d:54:4b:e5:8b", ip: "0.0.0.0", children: []*meshNode{ghostChild, live}}
	relay := &meshNode{mac: "aa:00:00:00:00:02", name: "G1TK7EY000012", ip: "192.168.200.193"}
	return &meshNode{mac: "aa:00:00:00:00:01", name: "G1TK7EY001160", ip: "192.168.200.1", hasHop: true, children: []*meshNode{ghost, relay}}
}

const liveTree = `
@ aa:00:00:00:00:01 - 192.168.200.1 - controller - G1TK7EY001160
== aa:00:00:00:00:02 - 192.168.200.193 - agent - G1TK7EY000012
== aa:00:00:00:00:03 - 192.168.200.15 - agent - G1TK7EY000096
`

func TestPruneEasyMeshGhostsKeepsLiveDescendants(t *testing.T) {
	root := ghostTopology()
	if removed := pruneEasyMeshGhosts(root, easyMeshLiveMACs(liveTree)); removed != 2 {
		t.Fatalf("removed=%d want 2", removed)
	}
	var names []string
	for _, node := range flattenMeshForest(normalizedMeshRoots(root)) {
		names = append(names, node.name)
	}
	if len(names) != 3 {
		t.Fatalf("remaining=%v want controller and two relays", names)
	}
	for _, child := range root.children {
		if child.name == "G1TK7EY000096" && child.parentMAC != root.mac {
			t.Fatalf("re-attached child parent=%q", child.parentMAC)
		}
	}
}

func TestPruneEasyMeshGhostsNeedsLiveEvidence(t *testing.T) {
	root := ghostTopology()
	if removed := pruneEasyMeshGhosts(root, map[string]bool{}); removed != 0 {
		t.Fatalf("pruned %d nodes without a live tree", removed)
	}
}

func TestRefreshTopologyRediscoversThenPublishesFullSnapshot(t *testing.T) {
	saved := easyMeshRediscoveryWait
	easyMeshRediscoveryWait = time.Millisecond
	t.Cleanup(func() { easyMeshRediscoveryWait = saved })
	var commands []easyMeshConsoleCommand
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UbusCaller: func(string, string, time.Duration) ([]byte, error) { return nil, wusp.ErrUSPPathUnsupported },
	})
	backend.easyMeshConsole = easyMeshConsoleFunc(func(_ context.Context, command easyMeshConsoleCommand) (string, error) {
		commands = append(commands, command)
		return "", nil
	})
	published := 0
	backend.SetEasyMeshObserver(func(*wusp.Message) { published++ })
	if _, err := backend.RunEasyMeshConsoleAction(context.Background(), "RefreshTopology"); err != nil {
		t.Fatal(err)
	}
	if len(commands) < 2 || commands[0] != easyMeshConsoleDiscovery || commands[1] != easyMeshConsoleNotification {
		t.Fatalf("commands=%v want discovery then notify first", commands)
	}
	if published != 1 {
		t.Fatalf("published=%d want one full snapshot", published)
	}
}
