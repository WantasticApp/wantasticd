//go:build !windows

package agent

func protectIPCDiscovery(data []byte) ([]byte, error) {
	return data, nil
}

func unprotectIPCDiscovery(data []byte) ([]byte, error) {
	return data, nil
}
