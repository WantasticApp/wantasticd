//go:build !linux

package platforms

import "net"

type linuxNeighborObservation struct {
	IP            net.IP
	MAC           net.HardwareAddr
	InterfaceName string
	State         uint16
	Active        bool
}

func readRouteNeighbors() ([]linuxNeighborObservation, error) { return nil, nil }
