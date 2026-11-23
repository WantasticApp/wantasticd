package platforms

import (
	"context"
	"log"
	"strings"
	"sync"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/osusers"
)

// osUsersRecorder keeps the outcome of the latest account Operate command so
// the next collection reports it in LastOperationStatus / Code / Message.
var osUsersRecorder = osusers.NewRecorder()

var (
	osUsersOnce    sync.Once
	osUsersBackend osusers.Backend
)

// osUsersFor returns the platform's account backend, built once. It is nil on
// a platform with no local-account surface.
func (b *hostBackend) osUsersFor() osusers.Backend {
	if !osUsersSupported || !desktopKind(b.kind) {
		return nil
	}
	osUsersOnce.Do(func() { osUsersBackend = newOSUsersBackend(b.commandRunner) })
	return osUsersBackend
}

// collectOSUsers fills Device.WUSP_OSUsers. with the device's local accounts
// and live sessions.
//
// The read is passive and runs only when a collect asks for it; nothing here
// changes an account. The account actions live in OSUsersOperate and run only
// when the console asks.
func (b *hostBackend) collectOSUsers(ctx context.Context, msg *wusp.Message) {
	backend := b.osUsersFor()
	installed := backend != nil
	enabled := osFeatureEnabled(featureOSUsers)

	snap := osusers.Snapshot{Platform: osUsersPlatform(b.kind)}
	if installed && enabled {
		read, err := backend.Collect(ctx)
		if err != nil {
			snap.Status = osusers.StatusReadError
			snap.StatusDetail = err.Error()
			if isPermissionError(err) {
				snap.Status = osusers.StatusPermissionDenied
			}
		} else {
			read.Platform = snap.Platform
			snap = read
			if snap.SupportedOperations == nil {
				snap.SupportedOperations = backend.SupportedOperations()
			}
		}
	}
	osusers.Append(msg, snap, installed, enabled, b.now(), osUsersRecorder)
}

func osUsersPlatform(kind Kind) string {
	switch kind {
	case KindMacOS:
		return osusers.PlatformMacOS
	case KindWindows:
		return osusers.PlatformWindows
	default:
		return ""
	}
}

// OSUsersOperate runs a Device.WUSP_OSUsers Operate command. It runs once,
// only when the console asks, and only when this device advertised it in
// SupportedOperations.
//
// A refusal is not a transport error: the console reads the closed-vocabulary
// code, so the reply carries LastOperationStatus=Error with the code.
func (b *hostBackend) OSUsersOperate(ctx context.Context, cmd string, input *wusp.Message) (*wusp.Message, error) {
	backend := b.osUsersFor()
	result := osusers.Operate(ctx, backend, osFeatureEnabled(featureOSUsers), cmd, input)
	osUsersRecorder.Record(result)
	// The message never holds the Password input, only the account name.
	log.Printf("[USP] OSUsers Operate: cmd=%s status=%s code=%s", strings.TrimSpace(cmd), result.Status, result.Code)
	return osusers.ResultMessage(result), nil
}

// setOSUsersParam applies a Device.WUSP_OSUsers. write. Enable is the only
// writable state leaf; the Operate inputs are write-only request fields that
// are never stored, so a Set of one is not a device write.
func setOSUsersParam(path string, value wusp.Value) error {
	if strings.TrimSpace(path) == wusp.WUSPOSUsersPrefix+"Enable" {
		return setOSFeatureEnabled(featureOSUsers, value.AsBool())
	}
	return wusp.ErrUSPPathUnsupported
}
