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

const (
	maxHostapdStations      = 4096
	maxHostapdResponseBytes = 64 * 1024
	maxHostapdTotalBytes    = 8 * 1024 * 1024
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
	for _, pattern := range []string{"/var/run/hostapd*", "/run/hostapd*", "/tmp/run/hostapd*", "/data/vendor/wifi/hostapd/ctrl*", "/data/misc/wifi/hostapd*"} {
		roots, _ := filepath.Glob(pattern)
		for _, root := range roots {
			add(filepath.Join(root, ifName))
		}
	}
	if len(paths) == 0 {
		// QCMAP (SDX) and other vendor builds put the control directory
		// wherever their hostapd.conf says; read it from the running daemons.
		for _, root := range hostapdConfiguredCtrlDirs() {
			add(filepath.Join(root, ifName))
		}
	}
	return paths
}

// hostapdConfiguredCtrlDirs returns ctrl_interface directories from the
// configuration files of running hostapd processes.
func hostapdConfiguredCtrlDirs() []string {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	var dirs []string
	seen := make(map[string]bool)
	for _, cmdlinePath := range procs {
		data, err := os.ReadFile(cmdlinePath)
		if err != nil || len(data) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if !strings.HasPrefix(filepath.Base(args[0]), "hostapd") {
			continue
		}
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "-") || !strings.HasSuffix(arg, ".conf") {
				continue
			}
			for _, dir := range parseHostapdCtrlInterface(readSmallFile(arg, 256<<10)) {
				if !seen[dir] {
					seen[dir] = true
					dirs = append(dirs, dir)
				}
			}
		}
		if len(dirs) >= 8 {
			break
		}
	}
	return dirs
}

func readSmallFile(path string, limit int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	buf := make([]byte, limit)
	n, _ := file.Read(buf)
	return string(buf[:n])
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
	buffer := make([]byte, maxHostapdResponseBytes)
	totalBytes := 0
	for {
		if err := conn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
			return nil, err
		}
		if _, err := conn.WriteToUnix([]byte(command), remote); err != nil {
			return nil, err
		}
		length, _, err := conn.ReadFromUnix(buffer)
		if err != nil {
			return nil, err
		}
		if length == len(buffer) {
			return nil, fmt.Errorf("hostapd station response reached the %d-byte safety limit", len(buffer))
		}
		totalBytes += length
		if totalBytes > maxHostapdTotalBytes {
			return nil, fmt.Errorf("hostapd station responses exceed the %d-byte safety limit", maxHostapdTotalBytes)
		}
		response := strings.TrimSpace(string(buffer[:length]))
		if response == "" || strings.HasPrefix(response, "FAIL") {
			break
		}
		if len(blocks) >= maxHostapdStations {
			return nil, fmt.Errorf("hostapd station count exceeds the %d-entry safety limit", maxHostapdStations)
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
