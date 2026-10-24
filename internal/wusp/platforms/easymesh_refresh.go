package platforms

import (
	"context"
	"net"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// easyMeshRediscoveryWait gives 1905 neighbors time to answer the topology
// discovery and notification a clean refresh sends before the tree is read.
var easyMeshRediscoveryWait = 2 * time.Second

// easyMeshLiveMACs is the set of 1905 AL MACs in the agent's live topology
// tree (td dtt detail). Unlike getRealTopo, which can keep devices that left
// the network until the vendor database ages them out, this tree only lists
// devices that answered recently.
func easyMeshLiveMACs(raw string) map[string]bool {
	live := make(map[string]bool)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		match := easyMeshConsoleTopologyTreeLine.FindStringSubmatch(line)
		if len(match) != 5 {
			continue
		}
		if mac, err := normalizeEasyMeshMAC(match[1]); err == nil {
			live[mac] = true
		}
	}
	return live
}

// easyMeshGhostCandidate is a node with nothing but a MAC: no address and no
// name, the shape stale vendor-database entries take.
func easyMeshGhostCandidate(node *meshNode) bool {
	if node == nil || meshNodeIsController(node) || normalizedEasyMeshHostname(node.name) != "" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(node.ip))
	return ip == nil || ip.IsUnspecified()
}

func easyMeshHasGhostCandidates(root *meshNode) bool {
	for _, node := range flattenMeshForest(normalizedMeshRoots(root)) {
		if easyMeshGhostCandidate(node) {
			return true
		}
	}
	return false
}

// pruneEasyMeshGhosts removes ghost candidates the live tree does not list.
// A ghost's children that are real are re-attached to the ghost's parent, so
// pruning never hides a live device. Nothing is pruned without live evidence.
func pruneEasyMeshGhosts(root *meshNode, live map[string]bool) int {
	if root == nil || len(live) == 0 {
		return 0
	}
	removed := 0
	isGhost := func(node *meshNode) bool {
		if !easyMeshGhostCandidate(node) {
			return false
		}
		mac, err := normalizeEasyMeshMAC(firstNonEmpty(node.mac, node.id))
		return err == nil && !live[mac]
	}
	var prune func(parent *meshNode, depth int)
	prune = func(parent *meshNode, depth int) {
		if parent == nil || depth > 32 {
			return
		}
		kept := make([]*meshNode, 0, len(parent.children))
		queue := append([]*meshNode(nil), parent.children...)
		for len(queue) > 0 {
			child := queue[0]
			queue = queue[1:]
			if child == nil {
				continue
			}
			if isGhost(child) {
				removed++
				for _, grandchild := range child.children {
					if grandchild != nil && !isSyntheticMeshRoot(parent) {
						grandchild.parentMAC = parent.mac
						grandchild.parentID = firstNonEmpty(parent.id, parent.mac)
					}
				}
				queue = append(queue, child.children...)
				continue
			}
			kept = append(kept, child)
		}
		parent.children = kept
		for _, child := range kept {
			prune(child, depth+1)
		}
	}
	prune(root, 0)
	return removed
}

// pruneEasyMeshGhostsLive reads the live tree only when the topology holds
// ghost candidates, so healthy meshes cost no extra console round trip.
func (b *OpenWrtBackend) pruneEasyMeshGhostsLive(ctx context.Context, root *meshNode) {
	if b == nil || b.easyMeshConsole == nil || !easyMeshHasGhostCandidates(root) {
		return
	}
	output, err := b.consoleRead(ctx, easyMeshConsoleTopologyTree, meshTreeMaxAge)
	if err != nil {
		return
	}
	pruneEasyMeshGhosts(root, easyMeshLiveMACs(output))
}

// refreshEasyMeshTopologyClean re-solicits the 1905 topology, then publishes
// a complete Node/Link snapshot rebuilt from scratch. Because the snapshot
// carries the table counts, the controller replaces its stored topology
// instead of merging into it, which clears departed devices.
func (b *OpenWrtBackend) refreshEasyMeshTopologyClean(ctx context.Context) error {
	for _, command := range []easyMeshConsoleCommand{easyMeshConsoleDiscovery, easyMeshConsoleNotification} {
		if _, err := b.consoleRun(ctx, command); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(easyMeshRediscoveryWait):
	}
	b.easyMeshOperationMu.RLock()
	observer := b.easyMeshObserver
	b.easyMeshOperationMu.RUnlock()
	if observer == nil {
		return nil
	}
	b.consoleInvalidate() // rebuild from the console as it is now
	patch := wusp.NewMessage()
	b.appendOpenWrtMeshTopology(ctx, patch)
	observer(patch)
	return nil
}
