package platforms

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// logCollectorError records a source-specific collection failure while allowing
// the remaining independent collectors to contribute their data-model fields.
func logCollectorError(collector string, err error) {
	if err != nil {
		log.Printf("[USP] Collector warning: source=%s continue_on_error=true err=%v", collector, err)
	}
}

// runCollector is the common continue-on-error boundary for independent data
// sources. A broken optional collector must never discard fields gathered by
// the other collectors or crash the long-running agent.
func runCollector(name string, collect func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
		logCollectorError(name, err)
	}()
	if collect == nil {
		return nil
	}
	return collect()
}

// isMissingTool reports whether err only says a command is not installed
// (macOS and Windows have no iptables-save). Such a source has nothing to
// collect on this host, which is not worth a warning every minute.
func isMissingTool(err error) bool {
	return err != nil && (errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found"))
}
