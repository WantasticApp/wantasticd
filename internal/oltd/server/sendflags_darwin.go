package server

// sendFlags: Darwin has no MSG_NOSIGNAL (tests only; the Go runtime
// ignores SIGPIPE on non-stdio descriptors anyway).
const sendFlags = 0
