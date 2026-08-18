//go:build linux

package iwinfo

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func getHostapdAssocList(ifName string) ([]AssocEntry, error) {
	paths := hostapdSocketPaths(ifName)
	var lastErr error
	for _, path := range paths {
		entries, err := queryHostapdSocket(path)
		if err == nil {
			return entries, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hostapd control socket for %s not found", ifName)
	}
	return nil, lastErr
}

func hostapdSocketPaths(ifName string) []string {
	seen := make(map[string]bool)
	paths := make([]string, 0, 8)
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for _, root := range []string{"/var/run/hostapd", "/run/hostapd", "/tmp/run/hostapd"} {
		add(filepath.Join(root, ifName))
	}
	for _, pattern := range []string{"/var/run/hostapd*", "/run/hostapd*", "/tmp/run/hostapd*"} {
		roots, _ := filepath.Glob(pattern)
		for _, root := range roots {
			add(filepath.Join(root, ifName))
		}
	}
	return paths
}

func queryHostapdSocket(remotePath string) ([]AssocEntry, error) {
	temp, err := os.CreateTemp("/tmp", "wantastic-hostapd-")
	if err != nil {
		return nil, err
	}
	localPath := temp.Name()
	_ = temp.Close()
	_ = os.Remove(localPath)
	defer os.Remove(localPath)

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: localPath, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	remote := &net.UnixAddr{Name: remotePath, Net: "unixgram"}

	blocks := make([]string, 0)
	command := "STA-FIRST"
	seen := make(map[string]bool)
	for len(blocks) < 4096 {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := conn.WriteToUnix([]byte(command), remote); err != nil {
			return nil, err
		}
		buffer := make([]byte, 64*1024)
		length, _, err := conn.ReadFromUnix(buffer)
		if err != nil {
			return nil, err
		}
		response := strings.TrimSpace(string(buffer[:length]))
		if response == "" || strings.HasPrefix(response, "FAIL") {
			break
		}
		entry, ok := parseHostapdStation(response)
		if !ok {
			return nil, fmt.Errorf("invalid hostapd station response")
		}
		mac := strings.ToLower(entry.MAC.String())
		if seen[mac] {
			break
		}
		seen[mac] = true
		blocks = append(blocks, response)
		command = "STA-NEXT " + mac
	}
	return ParseHostapdStations(blocks...), nil
}
