package exitnode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// State is the exit-node choice plus what is installed on the host. It lives
// in a local file next to the agent config (never in hub config) so the
// choice survives restarts and a crashed daemon's leftovers can be removed.
type State struct {
	// Offer: this device allows peers to use it as an exit node.
	Offer bool `json:"offer"`
	// Use: VPN IP of the peer this device sends its internet traffic through.
	Use string `json:"use,omitempty"`

	// Installed artifacts (crash cleanup).
	NAT                *NATState `json:"nat,omitempty"`
	ClientNAT          *NATState `json:"client_nat,omitempty"`
	Routes             []Route   `json:"routes,omitempty"`
	RouteTun           string    `json:"route_tun,omitempty"`
	RouteGW            Gateway   `json:"route_gw,omitempty"`
	ServerHadV4Default bool      `json:"server_had_v4_default,omitempty"`
}

// LoadState reads path; a missing file is an empty state (exists=false).
func LoadState(path string) (st State, exists bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, true, err
	}
	return st, true, nil
}

// SaveState writes path atomically, readable by root only.
func SaveState(path string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".exitnode-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
