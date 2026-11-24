package server

import "golang.org/x/sys/unix"

// sendFlags: never raise SIGPIPE on a peer that went away.
const sendFlags = unix.MSG_NOSIGNAL
