package diaglog

import (
	"log"
	"os"
	"strings"
)

const verboseEnv = "WANTASTIC_VERBOSE_LOGS"

// Enabled reports whether high-volume diagnostic logging was explicitly
// enabled. Routine collection and transport traces are quiet by default so
// warnings and state changes remain visible on constrained devices.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(verboseEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func Printf(format string, args ...any) {
	if Enabled() {
		log.Printf(format, args...)
	}
}
