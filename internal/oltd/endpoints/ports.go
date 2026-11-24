package endpoints

// Hand-ported bespoke endpoints (ports_*.go) register themselves with
// addPort from their file's init; portedEndpoints lists them for the
// catalog test. Each port is written from the tools/oltre trace of the
// vendor handler; the trace's addresses are quoted in the comments.

var portedEndpoints []*Endpoint

func addPort(e *Endpoint) {
	portedEndpoints = append(portedEndpoints, e)
	register(e)
}
