package platforms

import (
	"wantastic-agent/internal/auth"
)

func defaultWantasticStatePath(name string) string {
	return auth.PersistentFilePath(name)
}

func ensureStateParentDir(path string) error {
	return auth.EnsureParentDir(path, 0o755)
}
