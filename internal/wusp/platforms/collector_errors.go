package platforms

import (
	"fmt"
	"log"
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
