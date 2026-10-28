//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"syscall"
)

// writePortFile replaces the port file through a rename: the daemon usually
// runs as root and /tmp is world-writable, so writing through an existing
// path could follow a planted symlink.
func writePortFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wantasticd_ipc_port.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// portFileTrusted accepts a port file owned by root or by the current user,
// so another local user cannot steer clients to a port they listen on.
func portFileTrusted(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() {
		return false
	}
	return st.Uid == 0 || int(st.Uid) == os.Getuid()
}
