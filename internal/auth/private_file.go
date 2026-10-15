package auth

import "fmt"

// WritePrivateFile writes secret-bearing state with platform-native access
// controls. Unix uses mode 0600. Windows uses a protected DACL.
func WritePrivateFile(path string, data []byte) error {
	if err := EnsureParentDir(path, 0o700); err != nil {
		return fmt.Errorf("create private file directory: %w", err)
	}
	return writePrivateFile(path, data)
}

// CheckPrivateFilePermissions verifies that path is not readable by unrelated
// local users according to the host platform's permission model.
func CheckPrivateFilePermissions(path string) error {
	return checkPrivateFilePermissions(path)
}
